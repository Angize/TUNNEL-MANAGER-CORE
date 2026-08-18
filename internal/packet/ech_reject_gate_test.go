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
	"testing"
	"time"
)

func selfSignedTLSCert(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func x25519Pub(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func TestECHRejectionNeverYieldsAUsableConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cert := selfSignedTLSCert(t, "edge.example")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {

				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()

	for _, tc := range []struct {
		name          string
		alpn          []string
		goFingerprint bool
	}{
		{"browser-parrot", []string{"http/1.1"}, false},
		{"go-parrot", []string{"h2"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ech := buildECHConfigListN(t, echTestConfig{name: "public.example", key: x25519Pub(t)})
			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer raw.Close()

			conn, err := uEdgeHandshake(raw, "edge.example", ech, tc.alpn, tc.goFingerprint, handshakeTimeout)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("an ECH rejection produced a usable connection: the reject hook skipped certificate " +
					"verification and nothing downstream caught it — every CDN-fronted carrier is MITM-able")
			}
			if conn != nil {
				t.Fatalf("uEdgeHandshake returned both a connection and an error (%v) — the conn must be nil", err)
			}
			t.Logf("ECH rejection refused as expected: %v", err)
		})
	}
}
