package packet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type chWriteConn struct{ hello []byte }

func (c *chWriteConn) Write(p []byte) (int, error) {
	c.hello = append(c.hello, p...)
	return len(p), nil
}
func (c *chWriteConn) Read([]byte) (int, error)         { return 0, errors.New("no server") }
func (c *chWriteConn) Close() error                     { return nil }
func (c *chWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1} }
func (c *chWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443} }
func (c *chWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *chWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chWriteConn) SetWriteDeadline(time.Time) error { return nil }

func greaseCount(b []byte) int {
	n := 0
	for i := 0; i+1 < len(b); i++ {
		if b[i] == b[i+1] && b[i]&0x0f == 0x0a {
			n++
		}
	}
	return n
}

func TestTLSToEdgeUsesChromeFingerprintALPNh1(t *testing.T) {
	cc := &chWriteConn{}
	b := &TCP{isClient: true, ws: true, wsTLS: true}

	_, _ = b.tlsToEdge(cc, "1.2.3.4:443", "cdn.example.com", nil, false, handshakeTimeout)
	if len(cc.hello) == 0 {
		t.Fatal("no ClientHello was written")
	}

	if g := greaseCount(cc.hello); g < 2 {
		t.Fatalf("expected the Chrome fingerprint (multiple GREASE values), got %d — looks like Go's crypto/tls", g)
	}

	if !bytes.Contains(cc.hello, []byte("http/1.1")) {
		t.Fatal("ClientHello must advertise http/1.1 in ALPN")
	}

	alpnH2 := []byte{0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	if bytes.Contains(cc.hello, alpnH2) {
		t.Fatal("ALPN must not offer h2 (would break the HTTP/1.1 WebSocket upgrade)")
	}

	if !bytes.Contains(cc.hello, []byte("cdn.example.com")) {
		t.Fatal("without ECH the SNI should carry the hostname")
	}
}

func helloSeenBy(t *testing.T, alpn []string, goFingerprint bool) *tls.ClientHelloInfo {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
				got = &cp
				return nil, nil
			},
			Certificates: []tls.Certificate{fpTestCert(t)},
			NextProtos:   []string{"h2", "http/1.1"},
		})
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = s.Handshake()
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = uEdgeHandshake(cli, "cdn.example.com", nil, alpn, goFingerprint, handshakeTimeout)
	cli.Close()
	<-done
	if got == nil {
		t.Fatal("the server never parsed a ClientHello")
	}
	return got
}

func hasGREASE(suites []uint16) bool {
	for _, cs := range suites {
		if byte(cs>>8) == byte(cs) && cs&0x0f == 0x0a {
			return true
		}
	}
	return false
}

func TestGrpcPathUsesTheGoFingerprint(t *testing.T) {
	grpc := helloSeenBy(t, []string{"h2"}, true)
	if hasGREASE(grpc.CipherSuites) {
		t.Error("the grpc ClientHello carries GREASE — that is the browser fingerprint, in front of a call no browser can make")
	}
	if len(grpc.SupportedProtos) != 1 || grpc.SupportedProtos[0] != "h2" {
		t.Errorf("grpc ALPN = %v, want [h2] alone (grpc-go offers only h2; [h2 http/1.1] is the browser's list)", grpc.SupportedProtos)
	}

	ws := helloSeenBy(t, []string{"http/1.1"}, false)
	if !hasGREASE(ws.CipherSuites) {
		t.Error("the ws path lost its Chrome fingerprint (no GREASE) — that path must stay browser-shaped")
	}
	if len(ws.SupportedProtos) != 1 || ws.SupportedProtos[0] != "http/1.1" {
		t.Errorf("ws ALPN = %v, want [http/1.1]", ws.SupportedProtos)
	}
}

func fpTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "cdn.example.com"},
		DNSNames:  []string{"cdn.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestChromeSpecALPN(t *testing.T) {

	h1, err := chromeSpec([]string{"http/1.1"})
	if err != nil {
		t.Fatalf("chromeSpec(http/1.1) failed on the pinned Chrome parrot: %v", err)
	}
	assertALPN(t, h1, []string{"http/1.1"})

	h2, err := chromeSpec(nil)
	if err != nil {
		t.Fatalf("chromeSpec(nil) failed: %v", err)
	}
	assertALPN(t, h2, []string{"h2", "http/1.1"})
}

func assertALPN(t *testing.T, spec utls.ClientHelloSpec, want []string) {
	t.Helper()
	for _, ext := range spec.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			if len(a.AlpnProtocols) != len(want) {
				t.Fatalf("ALPN = %v, want %v", a.AlpnProtocols, want)
			}
			for i := range want {
				if a.AlpnProtocols[i] != want[i] {
					t.Fatalf("ALPN = %v, want %v", a.AlpnProtocols, want)
				}
			}
			return
		}
	}
	t.Fatal("no ALPN extension in the Chrome spec")
}
