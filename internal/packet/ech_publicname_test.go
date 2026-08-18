package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type echTestConfig struct {
	name   string
	kemID  uint16
	key    []byte
	bogusV bool
}

func buildECHConfigListN(t *testing.T, cfgs ...echTestConfig) []byte {
	t.Helper()
	var list cryptobyte.Builder
	list.AddUint16LengthPrefixed(func(lb *cryptobyte.Builder) {
		for _, c := range cfgs {
			kem := c.kemID
			if kem == 0 {
				kem = 0x20
			}
			key := c.key
			if key == nil {
				key = make([]byte, 32)
			}
			var contents cryptobyte.Builder
			contents.AddUint8(1)
			contents.AddUint16(kem)
			contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key) })
			contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
			contents.AddUint8(64)
			contents.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(c.name)) })
			contents.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})
			body := contents.BytesOrPanic()

			version := echConfigVersion
			if c.bogusV {
				version = 0xabcd
			}
			lb.AddUint16(version)
			lb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
		}
	})
	return list.BytesOrPanic()
}

func buildECHConfigList(t *testing.T, publicName string, bogusVersion bool) []byte {
	t.Helper()
	return buildECHConfigListN(t, echTestConfig{name: publicName, bogusV: bogusVersion})
}

func TestECHPublicNames(t *testing.T) {
	eq := func(got []string, want ...string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	if got := echPublicNames(buildECHConfigList(t, "cloudflare-ech.com", false)); !eq(got, "cloudflare-ech.com") {
		t.Fatalf("echPublicNames = %v, want [cloudflare-ech.com]", got)
	}

	if got := echPublicNames(buildECHConfigList(t, "cloudflare-ech.com", true)); len(got) != 0 {
		t.Fatalf("unknown-version config: echPublicNames = %v, want empty", got)
	}

	multi := buildECHConfigListN(t,
		echTestConfig{name: "unsupported-kem.example", kemID: 0x99},
		echTestConfig{name: "cloudflare-ech.com"},
	)
	if got := echPublicNames(multi); !eq(got, "unsupported-kem.example", "cloudflare-ech.com") {
		t.Fatalf("echPublicNames = %v, want both names so the one uTLS picks is covered", got)
	}

	for _, bad := range [][]byte{nil, {}, {0x00}, {0xff, 0xff, 0x00}, []byte("not-an-ech-config")} {
		if got := echPublicNames(bad); len(got) != 0 {
			t.Fatalf("echPublicNames(%v) = %v, want empty", bad, got)
		}
	}
}

func makeLeaf(t *testing.T, dnsName string) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return leaf, roots
}

func TestVerifyOuterCert(t *testing.T) {
	leaf, roots := makeLeaf(t, "cloudflare-ech.com")

	if err := verifyOuterCert([]*x509.Certificate{leaf}, "cloudflare-ech.com", roots); err != nil {
		t.Fatalf("valid public-name cert should verify: %v", err)
	}

	if err := verifyOuterCert([]*x509.Certificate{leaf}, "evil.example", roots); err == nil {
		t.Fatal("cert for cloudflare-ech.com must NOT verify against a different public name")
	}

	if err := verifyOuterCert([]*x509.Certificate{leaf}, "cloudflare-ech.com", x509.NewCertPool()); err == nil {
		t.Fatal("cert not chaining to a trusted root must NOT verify")
	}

	if err := verifyOuterCert(nil, "cloudflare-ech.com", roots); err == nil {
		t.Fatal("verifyOuterCert with no peer cert must error")
	}
}
