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

// selfSignedTLSCert mints a throwaway self-signed leaf usable by a crypto/tls server.
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

// x25519Pub returns a REAL X25519 public key. The all-zero placeholder the parser tests use is a
// low-order point that HPKE refuses, which would fail ECH setup before a handshake ever starts.
func x25519Pub(t *testing.T) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// TestECHRejectionNeverYieldsAUsableConn drives the real uEdgeHandshake against a real TLS 1.3 server
// that has no ECH keys — which IS an ECH rejection — and asserts that no usable connection comes back.
//
// This is the invariant the reject-verify hook silently rests on. To surface the fresh RetryConfigList
// for the in-band self-heal we must let uTLS proceed past its own certificate check, so the hook
// accepts the outer certificate UNVERIFIED. That is only safe because uTLS always turns a rejected ECH
// into an error: it refuses to offer anything below TLS 1.3 once an ECH config list is set, so no
// downgrade reaches the hook and then completes, and the TLS 1.3 path sends alertECHRequired and
// returns *ECHRejectionError before marking the handshake complete. Neither of those facts is ours,
// and a uTLS bump could take either away — at which point we would be holding a TLS session whose
// certificate NOBODY checked, i.e. an open MITM window on every carrier that fronts through a CDN.
//
// uEdgeHandshake now fails closed if the hook fired and the handshake nevertheless succeeded, so this
// test stays green either way; what it locks is the OBSERVABLE property — an ECH rejection never
// hands a connection back — which is what turns a uTLS regression into a red test instead of a
// silent downgrade of the whole ws/http/grpc family.
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
				// A perfectly ordinary TLS 1.3 server. It knows nothing about ECH, so it echoes no
				// acceptance — exactly what a stale ECH key looks like from the client's side.
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()

	ech := buildECHConfigListN(t, echTestConfig{name: "public.example", key: x25519Pub(t)})
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	conn, err := uEdgeHandshake(raw, "edge.example", ech, nil)
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
}
