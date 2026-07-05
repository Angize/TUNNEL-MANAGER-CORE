package tlscover

import (
	"bufio"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// realDest stands in for the borrowed site: a normal TLS server with a
// recognizable cert CN that greets whoever completes a handshake.
func realDest(t *testing.T, cn string) (addr string) {
	t.Helper()
	cert, err := SelfSignedCert(cn)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.Write([]byte("HELLO-FROM-REAL\n")); time.Sleep(200 * time.Millisecond); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// coverServer runs a REALITY-style cover pointing at destAddr.
func coverServer(t *testing.T, psk, destAddr string) (addr string) {
	t.Helper()
	sv, err := NewServer(psk, "real.example")
	if err != nil {
		t.Fatal(err)
	}
	sv.dest = destAddr // override the :443 dest for the test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c, err := sv.Handle(raw, time.Now().Add(5*time.Second))
				if err != nil {
					return // ErrProbe (proxied) or a bad hello
				}
				c.Write([]byte("TUNNEL-OK\n")) // authenticated client
			}()
		}
	}()
	return ln.Addr().String()
}

// TestCoverAuthenticatedClient: our client (with the token) terminates at the
// cover server and gets the tunnel greeting, not the real site.
func TestCoverAuthenticatedClient(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := realDest(t, "real.example")
	cov := coverServer(t, psk, dest)

	raw, err := net.Dial("tcp", cov)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ClientConn(raw, "real.example", psk, time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatalf("authenticated handshake: %v", err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "TUNNEL-OK\n" {
		t.Fatalf("authenticated client got %q, want the tunnel greeting", line)
	}
}

// TestCoverProbeSeesRealSite: a probe (a plain TLS client WITHOUT the token) is
// transparently proxied to the real dest, so it completes a handshake against
// the real site's certificate and reads the real site's bytes — active-probe
// resistance.
func TestCoverProbeSeesRealSite(t *testing.T) {
	const psk = "reality-psk-abcdefghij"
	dest := realDest(t, "real.example")
	cov := coverServer(t, psk, dest)

	c, err := tls.Dial("tcp", cov, &tls.Config{InsecureSkipVerify: true, ServerName: "real.example"})
	if err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	defer c.Close()
	cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName
	if cn != "real.example" {
		t.Fatalf("probe saw cert CN %q — expected the REAL dest, cover leaked its own cert", cn)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "HELLO-FROM-REAL\n" {
		t.Fatalf("probe read %q, want the real site's bytes", line)
	}
}
