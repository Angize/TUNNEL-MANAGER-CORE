package packet

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func caSignedTLSCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ech-redial-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}, roots
}

func echServerConfig(pub []byte, publicName string) []byte {
	var c cryptobyte.Builder
	c.AddUint8(1)
	c.AddUint16(0x0020)
	c.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
	c.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
	c.AddUint8(64)
	c.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
	c.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})
	body := c.BytesOrPanic()
	var one cryptobyte.Builder
	one.AddUint16(echConfigVersion)
	one.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
	return one.BytesOrPanic()
}

func TestEveryDialledConnectionGetsDecoysAcrossTheECHRedial(t *testing.T) {
	leaf, caPool := caSignedTLSCert(t, "public.example")

	srvKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	serverECH := echServerConfig(srvKey.PublicKey().Bytes(), "public.example")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	accepted := 0
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			accepted++
			mu.Unlock()
			go func(c net.Conn) {
				tc := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{leaf},
					MinVersion:   tls.VersionTLS13,
					EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
						Config: serverECH, PrivateKey: srvKey.Bytes(), SendAsRetry: true,
					}},
				})
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tc.Handshake()
				tc.Close()
			}(c)
		}
	}()

	staleKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	stale := buildECHConfigListN(t, echTestConfig{name: "public.example", key: staleKey.PublicKey().Bytes()})

	prevRoots := echVerifyRoots
	echVerifyRoots = caPool
	t.Cleanup(func() { echVerifyRoots = prevRoots })

	var decoyed []net.Conn
	b := &TCP{
		addr: ln.Addr().String(), ws: true, wsTLS: true,
		wsHost: "public.example", wsPath: "/", wsECH: stale, isClient: true,
	}
	b.dsWatch = func(c net.Conn) {
		mu.Lock()
		decoyed = append(decoyed, c)
		mu.Unlock()
	}

	if conn, _, _, eerr := b.establishWS(); eerr == nil {
		conn.Close()
		t.Fatal("establishWS succeeded against a privately-signed edge; the self-heal path was not exercised")
	}

	mu.Lock()
	gotAccepted, gotDecoyed := accepted, len(decoyed)
	mu.Unlock()
	if gotAccepted < 2 {
		t.Fatalf("the edge accepted %d connection(s): the ECH self-heal redial never happened, so this test proves nothing", gotAccepted)
	}
	if gotDecoyed != gotAccepted {
		t.Errorf("%d connections dialled but only %d got decoys — the connection produced by the ECH self-heal redial is the one that carries the tunnel, and on a Cloudflare key rotation that is EVERY client's first dial",
			gotAccepted, gotDecoyed)
	}
}
