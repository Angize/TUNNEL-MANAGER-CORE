package packet

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func echoHTTPC() *httptest.Server {
	type sess struct {
		pr   *io.PipeReader
		pw   *io.PipeWriter
		mu   sync.Mutex
		next uint64
		pend map[uint64][]byte
	}
	var mu sync.Mutex
	sessions := map[string]*sess{}
	get := func(sid string) *sess {
		mu.Lock()
		defer mu.Unlock()
		if s := sessions[sid]; s != nil {
			return s
		}
		pr, pw := io.Pipe()
		s := &sess{pr: pr, pw: pw, pend: map[uint64][]byte{}}
		sessions[sid] = s
		return s
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s := get(r.URL.Query().Get("s"))
		if r.Method == http.MethodPost {
			seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
			data, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.pend[seq] = data
			for {
				d, ok := s.pend[s.next]
				if !ok {
					break
				}
				delete(s.pend, s.next)
				s.next++
				if len(d) > 0 {
					s.pw.Write(d)
				}
			}
			s.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fl := w.(http.Flusher)
		w.WriteHeader(200)
		fl.Flush()
		go func() { <-r.Context().Done(); s.pw.Close() }()
		buf := make([]byte, 4096)
		for {
			n, e := s.pr.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				fl.Flush()
			}
			if e != nil {
				return
			}
		}
	})
	return httptest.NewServer(mux)
}

func TestHTTPCProbeUsesRealEstablish(t *testing.T) {
	good := echoHTTPC()
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer bad.Close()

	probe := func(addr string) bool {
		b := &TCP{addr: addr, ws: true, httpc: true, wsPath: "/", wsTLS: false}
		return b.probeEdgeFull(addr, wsSNIEntry{path: "/"})
	}
	if !probe(good.Listener.Addr().String()) {
		t.Fatal("a working httpc origin must probe healthy")
	}
	if probe(bad.Listener.Addr().String()) {
		t.Fatal("a 502-origin behind a reachable front must probe DEAD (a TLS-only probe would wrongly pass it)")
	}
}

func TestHTTPCGrpcProbeHealthyOnRealOrigin(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "xhgprobe")
	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.httpcHandler)
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })

	b := &TCP{addr: ts.Listener.Addr().String(), ws: true, httpc: true, httpcMode: "grpc", wsPath: "/",
		wsTLS: true, httpcTLS: &tls.Config{InsecureSkipVerify: true}}
	if !b.probeEdgeFull(ts.Listener.Addr().String(), wsSNIEntry{path: "/"}) {
		t.Fatal("a real grpc httpc origin must probe healthy")
	}
}

func TestHTTPCCarrierRoundTrip(t *testing.T) {
	srv := echoHTTPC()
	defer srv.Close()
	b := &TCP{addr: srv.Listener.Addr().String(), wsPath: "/", wsTLS: false}
	conn, _, _, err := b.establishHTTPC()
	if err != nil {
		t.Fatalf("establishHTTPC: %v", err)
	}
	defer conn.Close()

	msgs := [][]byte{[]byte("hello http"), []byte("second frame"), make([]byte, 5000)}
	for i := range msgs[2] {
		msgs[2][i] = byte(i)
	}
	go func() {
		for _, m := range msgs {
			conn.Write(m)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	want := append(append([]byte("hello http"), []byte("second frame")...), msgs[2]...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < len(want) {
		n, e := conn.Read(buf)
		got = append(got, buf[:n]...)
		if e != nil {
			t.Fatalf("read after %d bytes: %v", len(got), e)
		}
	}
	if string(got) != string(want) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
	t.Logf("httpc round-tripped %d bytes both ways", len(got))
}

func httpcInject(t *testing.T, cliCtrl, srvCtrl *os.File) {
	t.Helper()
	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}
	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}
	pkt3 := bytes.Repeat([]byte{0x33}, 120)
	if _, err := cliCtrl.Write(pkt3); err != nil {
		t.Fatalf("inject client->server #2: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server #2"); !bytes.Equal(got, pkt3) {
		t.Fatalf("client->server #2 payload mismatch")
	}
}

func TestTunnelHTTPCPost(t *testing.T) { testTunnelHTTPC(t, "post", false) }

func TestTunnelHTTPCPostObfs(t *testing.T) { testTunnelHTTPC(t, "post", true) }

func testTunnelHTTPC(t *testing.T, mode string, obfs bool) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "xhsrv")
	cliDev, cliCtrl := tunPair(t, "xhcli")
	ka := 1 * time.Second
	addr := freeTCPPort(t)

	srv, err := ListenHTTPC(addr, srvDev, ka, obfs, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}

	cli, err := DialHTTPC(addr, cliDev, ka, obfs, true, psk, cipher, "", "/", false, nil, mode)
	if err != nil {
		t.Fatalf("DialHTTPC: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(400 * time.Millisecond)
	httpcInject(t, cliCtrl, srvCtrl)
}

func TestGrpcFraming(t *testing.T) {
	var buf bytes.Buffer
	w := &grpcFramingWriter{w: &buf}
	msgs := [][]byte{[]byte("hello grpc"), []byte("second frame"), bytes.Repeat([]byte{0xAB}, 5000)}
	var want []byte
	for _, m := range msgs {
		if _, err := w.Write(m); err != nil {
			t.Fatalf("frame write: %v", err)
		}
		want = append(want, m...)
	}
	r := &grpcDeframingReader{r: &buf}
	got := make([]byte, 0, len(want))
	tmp := make([]byte, 128)
	for len(got) < len(want) {
		n, err := r.Read(tmp)
		got = append(got, tmp[:n]...)
		if err != nil {
			t.Fatalf("deframe read after %d bytes: %v", len(got), err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("grpc framing round-trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestTunnelHTTPCGrpc(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "xhgsrv")
	cliDev, cliCtrl := tunPair(t, "xhgcli")
	ka := 1 * time.Second

	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, ka, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.httpcHandler)
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })

	cli, err := DialHTTPC(ts.Listener.Addr().String(), cliDev, ka, false, true, psk, cipher, "", "/", true, nil, "grpc")
	if err != nil {
		t.Fatalf("DialHTTPC: %v", err)
	}
	cli.httpcTLS = &tls.Config{InsecureSkipVerify: true}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	time.Sleep(600 * time.Millisecond)
	httpcInject(t, cliCtrl, srvCtrl)
}

func TestHTTPCServerH2C(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "h2csrv")
	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(150 * time.Millisecond)

	hc := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	resp, err := hc.Get("http://" + srv.ln.Addr().String() + "/?s=notavalidsessionid")
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2 (h2c), got %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a bad sid, got %d", resp.StatusCode)
	}
}

func TestSourceIPBind(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			seen <- "accept-err"
			return
		}
		seen <- c.RemoteAddr().(*net.TCPAddr).IP.String()
		c.Close()
	}()
	b := &TCP{bindIP: "127.0.0.2"}
	c, err := b.dialer(2*time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with bound source: %v", err)
	}
	defer c.Close()
	select {
	case src := <-seen:
		if src != "127.0.0.2" {
			t.Fatalf("server saw source %s, want 127.0.0.2 (bind not applied)", src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no connection observed")
	}
}

func TestDoWithHeaderTimeout(t *testing.T) {

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fast.Close()
	freq, _ := http.NewRequest("GET", fast.URL, nil)
	resp, err := doWithHeaderTimeout(fast.Client(), freq, 2*time.Second)
	if err != nil {
		t.Fatalf("fast path returned error: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("fast path status %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()

	served := make(chan struct{})
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(served)
		<-r.Context().Done()
	}))
	defer stall.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sreq, _ := http.NewRequestWithContext(ctx, "GET", stall.URL, nil)
	start := time.Now()
	if _, err := doWithHeaderTimeout(stall.Client(), sreq, 200*time.Millisecond); err == nil {
		t.Fatal("stall path returned nil error (should have timed out)")
	} else if !strings.Contains(err.Error(), "response-header timeout") {
		t.Fatalf("stall path wrong error: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("stall path took %v (should be ~200ms)", el)
	}
	<-served
	cancel()
}

func TestHTTPCConnReadDeadline(t *testing.T) {
	pr, _ := io.Pipe()
	c := &httpcConn{r: pr, w: io.Discard}
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	start := time.Now()
	buf := make([]byte, 8)
	_, err := c.Read(buf)
	if err == nil {
		t.Fatal("expected read error after deadline")
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("deadline took too long: %v", d)
	}
}
