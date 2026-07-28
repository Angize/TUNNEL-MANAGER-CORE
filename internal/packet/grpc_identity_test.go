package packet

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGrpcRequestIsNotABrowser drives a REAL grpc-mode tunnel and inspects the request that actually
// reached the origin — not the helper that builds the headers.
//
// The request used to claim Chrome (User-Agent, Accept-Language, Cache-Control) while also carrying
// Content-Type: application/grpc and TE: trailers, which browser fetch/XHR is forbidden to set, and
// omitting grpc-accept-encoding, which every real gRPC client sends. That combination exists nowhere:
// it is a browser making a call no browser can make, and it is precisely what a gRPC-aware WAF keys
// on. The operator saw only `http/grpc: got HTTP 4xx`.
//
// The TLS half of the same identity is TestGrpcPathUsesTheGoFingerprint. Both must hold: fixing one
// alone relocates the mismatch (a grpc-go User-Agent under a Chrome JA3 is the same lie reversed).
func TestGrpcRequestIsNotABrowser(t *testing.T) {
	const psk = "grpc-identity-psk-abcdefghijklmno"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "grpcidsrv")
	cliDev, cliCtrl := tunPair(t, "grpcidcli")
	ka := time.Second

	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	var mu sync.Mutex
	var seen http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if seen == nil {
			seen = r.Header.Clone()
		}
		mu.Unlock()
		srv.httpcHandler(w, r)
	})
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run()
	// Core server FIRST: httptest.Server.Close waits for outstanding handlers, and the downstream
	// handler parks on <-s.done until the core session ends. Closing ts first waits out the server's
	// whole idle window before that ever happens.
	t.Cleanup(func() { srv.Close(); ts.Close() })

	cli, err := DialHTTPC(ts.Listener.Addr().String(), cliDev, ka, false, true, psk, cipher, "", "/", true, nil, "grpc")
	if err != nil {
		t.Fatalf("DialHTTPC: %v", err)
	}
	cli.httpcTLS = &tls.Config{InsecureSkipVerify: true}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 6*time.Second, "the grpc carrier reached the origin", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen != nil
	})
	// The first request reaches the handler BEFORE the core handshake completes, so wait for the
	// carrier to actually be live before injecting — otherwise tunLoop drops the packet on the floor
	// and the round-trip times out under load.
	waitFor(t, 6*time.Second, "the tunnel came up", func() bool { return cli.cur.Load() != nil })
	httpcInject(t, cliCtrl, srvCtrl) // the identity change must not break the carrier it dresses
	mu.Lock()
	h := seen
	mu.Unlock()

	// It must look like the gRPC client it is.
	if ua := h.Get("User-Agent"); !strings.HasPrefix(ua, "grpc-go/") {
		t.Errorf("User-Agent = %q, want a grpc-go client on a request carrying application/grpc", ua)
	}
	if got := h.Get("Content-Type"); !strings.HasPrefix(got, "application/grpc") {
		t.Errorf("Content-Type = %q, want application/grpc", got)
	}
	if got := h.Get("Te"); got != "trailers" {
		t.Errorf("TE = %q, want trailers", got)
	}
	if h.Get("Grpc-Accept-Encoding") == "" {
		t.Error("grpc-accept-encoding is missing — every real gRPC client advertises one")
	}

	// ...and it must NOT carry a single header a browser would add. These are the tell.
	for _, banned := range []string{"Accept-Language", "Cache-Control", "Accept-Encoding"} {
		if v := h.Get(banned); v != "" {
			t.Errorf("a gRPC request carries %s: %q — no gRPC client sends that, and no browser can send application/grpc", banned, v)
		}
	}
	// grpc-go sets grpc-encoding only when it is actually compressing, so "identity" is its own tell.
	if v := h.Get("Grpc-Encoding"); v != "" {
		t.Errorf("grpc-encoding: %q is set with no compression in use; grpc-go omits the header entirely", v)
	}
}

// TestCarrierWiresTheRightFingerprint covers the WIRING, not the switch: a correct goFingerprint
// branch in uEdgeHandshake proves nothing if establishHTTPC passes the wrong flag. It drives the real
// establishHTTPC over real TLS (no httpcTLS override, so the production uTLS branch runs) into a
// server that records the ClientHello it parsed. The handshake fails on the self-signed certificate —
// by then the hello is already on the wire, which is all this is about.
func TestCarrierWiresTheRightFingerprint(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		wantGREASE  bool
		wantALPN    string
		description string
	}{
		{"grpc", false, "h2", "a gRPC call must not be fronted by a browser ClientHello"},
		{"post", true, "http/1.1", "the POST ladder's page-fetch-shaped requests keep the browser ClientHello"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var mu sync.Mutex
			var got *tls.ClientHelloInfo
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				s := tls.Server(c, &tls.Config{
					GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
						cp := *chi
						mu.Lock()
						got = &cp
						mu.Unlock()
						return nil, nil
					},
					Certificates: []tls.Certificate{fpTestCert(t)},
					NextProtos:   []string{"h2", "http/1.1"},
				})
				c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = s.Handshake()
			}()

			dev, _ := tunPair(t, "fpwire"+tc.mode)
			cli, err := DialHTTPC(ln.Addr().String(), dev, time.Second, false, true,
				"fingerprint-wiring-psk-abcdefghij", "aes-256-gcm", "cdn.example.com", "/", true, nil, tc.mode)
			if err != nil {
				t.Fatalf("DialHTTPC: %v", err)
			}
			t.Cleanup(func() { cli.Close() })
			if _, _, _, err := cli.establishHTTPC(false); err == nil {
				t.Fatal("the establish should have failed on the self-signed certificate")
			}
			<-done

			mu.Lock()
			hi := got
			mu.Unlock()
			if hi == nil {
				t.Fatal("the server never parsed a ClientHello — the carrier did not reach the TLS layer")
			}
			if hasGREASE(hi.CipherSuites) != tc.wantGREASE {
				t.Errorf("%s: GREASE present = %v, want %v (%s)", tc.mode, !tc.wantGREASE, tc.wantGREASE, tc.description)
			}
			if len(hi.SupportedProtos) != 1 || hi.SupportedProtos[0] != tc.wantALPN {
				t.Errorf("%s: ALPN = %v, want [%s]", tc.mode, hi.SupportedProtos, tc.wantALPN)
			}
		})
	}
}

// TestPostLadderStaysBrowserShaped is the other side of the same coin: the POST ladder's requests
// really are shaped like page fetches, so they must KEEP the browser identity that matches the Chrome
// ClientHello on that path. A fix that made every mode look like grpc-go would break this.
func TestPostLadderStaysBrowserShaped(t *testing.T) {
	const psk = "post-identity-psk-abcdefghijklmno"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "postidsrv")
	cliDev, cliCtrl := tunPair(t, "postidcli")
	ka := time.Second

	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	var mu sync.Mutex
	var seen http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if seen == nil {
			seen = r.Header.Clone()
		}
		mu.Unlock()
		srv.httpcHandler(w, r)
	})
	ts := httptest.NewServer(mux)
	go srv.Run()
	// Core server FIRST: httptest.Server.Close waits for outstanding handlers, and the downstream
	// handler parks on <-s.done until the core session ends. Closing ts first waits out the server's
	// whole idle window before that ever happens.
	t.Cleanup(func() { srv.Close(); ts.Close() })

	cli, err := DialHTTPC(ts.Listener.Addr().String(), cliDev, ka, false, true, psk, cipher, "", "/", false, nil, "post")
	if err != nil {
		t.Fatalf("DialHTTPC: %v", err)
	}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 6*time.Second, "the post-ladder carrier reached the origin", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen != nil
	})
	waitFor(t, 6*time.Second, "the tunnel came up", func() bool { return cli.cur.Load() != nil })
	httpcInject(t, cliCtrl, srvCtrl)
	mu.Lock()
	h := seen
	mu.Unlock()

	if ua := h.Get("User-Agent"); !strings.Contains(ua, "Chrome/") {
		t.Errorf("POST-ladder User-Agent = %q, want the browser identity that matches its Chrome ClientHello", ua)
	}
	if h.Get("Accept-Language") == "" {
		t.Error("the POST ladder lost Accept-Language — its requests are page-fetch shaped and should stay so")
	}
	if ct := h.Get("Content-Type"); strings.HasPrefix(ct, "application/grpc") {
		t.Errorf("the POST ladder is sending %q — the grpc identity leaked onto the browser-shaped path", ct)
	}
}
