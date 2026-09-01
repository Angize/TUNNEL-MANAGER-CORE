package packet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func echListFor(t *testing.T, publicName string) []byte {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return buildECHConfigListN(t, echTestConfig{name: publicName, key: k.PublicKey().Bytes()})
}

// ECH exists to keep the real hostname off the wire, and nothing anywhere asserted that it does. The
// only hello-content test covers the ECH-OFF case (TestTLSToEdgeUsesChromeFingerprintALPNh1), which
// asserts the OPPOSITE: that the hostname IS in the ClientHello. So every way ECH could silently fail
// open -- a config list uTLS declines, a public name that does not parse, a fragmenter that writes the
// inner hello -- would have left the real host in cleartext with a green test suite.
//
// The outer SNI must be the ECH public name, the real host must not appear anywhere in the bytes that
// leave, and the ECH extension (0xfe0d) must be present.
func TestTheRealHostIsNotInTheClientHello(t *testing.T) {
	const real = "secret-origin.example.net"
	const public = "cloudflare-ech.com"

	ech := echListFor(t, public)
	cc := &chWriteConn{}
	b := &TCP{isClient: true, ws: true, wsTLS: true}
	_, _ = b.tlsToEdge(cc, "1.2.3.4:443", real, ech, false, handshakeTimeout)

	if len(cc.hello) == 0 {
		t.Fatal("no ClientHello was written")
	}
	if bytes.Contains(cc.hello, []byte(real)) {
		t.Fatalf("the real hostname %q is in the ClientHello ECH was configured to hide", real)
	}
	if !bytes.Contains(cc.hello, []byte(public)) {
		t.Fatalf("the outer SNI is not the ECH public name %q", public)
	}
	if !bytes.Contains(cc.hello, []byte{0xfe, 0x0d}) {
		t.Fatal("no encrypted_client_hello extension (0xfe0d) in the ClientHello")
	}
}

// The same guarantee through the fragmenting writers, which are what actually put the bytes on the
// socket when sni_split or sni_mode is on: they cut the record up, and a cut that reordered or
// duplicated the wrong half would put the inner hello on the wire.
func TestTheRealHostSurvivesNoFragmentationMode(t *testing.T) {
	const real = "secret-origin.example.net"
	const public = "cloudflare-ech.com"
	ech := echListFor(t, public)

	for _, tc := range []struct {
		name  string
		build func() *TCP
	}{
		{"plain", func() *TCP { return &TCP{isClient: true, ws: true, wsTLS: true} }},
		{"sni_split", func() *TCP {
			b := &TCP{isClient: true, ws: true, wsTLS: true}
			b.SetSNISplit(true, 0, "", 0)
			return b
		}},
		{"sni_mode=fake", func() *TCP {
			b := &TCP{isClient: true, ws: true, wsTLS: true}
			b.SetSNISplit(true, 0, "fake", 0)
			return b
		}},
	} {
		cc := &chWriteConn{}
		_, _ = tc.build().tlsToEdge(cc, "1.2.3.4:443", real, ech, false, handshakeTimeout)
		if len(cc.hello) == 0 {
			t.Fatalf("%s: no ClientHello was written", tc.name)
		}
		if bytes.Contains(cc.hello, []byte(real)) {
			t.Errorf("%s: the real hostname reached the wire", tc.name)
		}
	}
}
