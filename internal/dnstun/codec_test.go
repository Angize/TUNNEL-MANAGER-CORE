package dnstun

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestNewCodecZoneNormalization(t *testing.T) {
	for _, in := range []string{"t.example.com", "t.example.com.", "T.Example.Com", " t.example.com "} {
		c, err := NewCodec(in)
		if err != nil {
			t.Fatalf("NewCodec(%q): %v", in, err)
		}
		if c.Zone() != "t.example.com." {
			t.Fatalf("NewCodec(%q) zone = %q, want t.example.com.", in, c.Zone())
		}
	}
	for _, bad := range []string{"", "   ", ".."} {
		if _, err := NewCodec(bad); err == nil {
			t.Errorf("NewCodec(%q) accepted a malformed zone", bad)
		}
	}
}

func TestNameRoundTrip(t *testing.T) {
	c, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxUpstream() < 16 {
		t.Fatalf("MaxUpstream = %d, implausibly small", c.MaxUpstream())
	}
	for _, size := range []int{0, 1, 5, 31, c.MaxUpstream() - 1, c.MaxUpstream()} {
		if size < 0 {
			continue
		}
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		name, err := c.EncodeName(data, newNonce())
		if err != nil {
			t.Fatalf("EncodeName(%d bytes): %v", size, err)
		}
		if wire := zoneWireLen(strings.ToLower(name)); wire > maxName {
			t.Fatalf("EncodeName(%d) produced a %d-byte name > %d limit", size, wire, maxName)
		}
		got, err := c.DecodeName(name)
		if err != nil {
			t.Fatalf("DecodeName(%d bytes): %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("round-trip mismatch at %d bytes: got %x want %x", size, got, data)
		}
	}
}

func TestNameOverCapacityRejected(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.EncodeName(make([]byte, c.MaxUpstream()+1), newNonce()); err == nil {
		t.Fatal("EncodeName accepted an over-capacity datagram")
	}
}

func TestEncodeNameRejectsBadNonce(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.EncodeName([]byte{1, 2, 3}, ""); err == nil {
		t.Fatal("EncodeName accepted an empty nonce")
	}
	if _, err := c.EncodeName([]byte{1, 2, 3}, strings.Repeat("a", maxLabel+1)); err == nil {
		t.Fatal("EncodeName accepted an over-long nonce")
	}
}

func TestNonceMakesEveryNameUnique(t *testing.T) {

	c, _ := NewCodec("t.example.com")
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		name, err := c.EncodeName(nil, newNonce())
		if err != nil {
			t.Fatal(err)
		}
		if seen[name] {
			t.Fatalf("duplicate poll name %q — resolver could cache/coalesce it", name)
		}
		seen[name] = true

		got, derr := c.DecodeName(name)
		if derr != nil || len(got) != 0 {
			t.Fatalf("poll name %q decoded to %x (err %v), want empty", name, got, derr)
		}
	}
}

func TestDecodeName0x20CaseRandomization(t *testing.T) {

	c, _ := NewCodec("t.example.com")
	data := make([]byte, 40)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	name, _ := c.EncodeName(data, newNonce())

	rc := []rune(name)
	for i := range rc {
		if i%2 == 0 {
			rc[i] = []rune(strings.ToUpper(string(rc[i])))[0]
		}
	}
	got, err := c.DecodeName(string(rc))
	if err != nil {
		t.Fatalf("DecodeName on case-randomized name: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("0x20 case randomization corrupted the decoded datagram")
	}
}

func TestDecodeNameRejectsForeignZone(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	if _, err := c.DecodeName("abcd.evil.example.net."); err == nil {
		t.Fatal("DecodeName accepted a name outside the zone")
	}
}

func TestDecodeNameRejectsSharedSuffixLabel(t *testing.T) {

	c, _ := NewCodec("t.example.com")
	if _, err := c.DecodeName("abt.example.com."); err == nil {
		t.Fatal("DecodeName accepted a name whose last label merely ends with the zone")
	}
}

func TestDecodeBareZoneIsRejected(t *testing.T) {

	c, _ := NewCodec("t.example.com")
	got, err := c.DecodeName("t.example.com.")
	if !errors.Is(err, ErrBareZone) {
		t.Fatalf("DecodeName(bare zone) = (%v, %v), want ErrBareZone", got, err)
	}
}

func TestTXTRoundTrip(t *testing.T) {
	c, _ := NewCodec("t.example.com")
	for _, size := range []int{0, 1, 100, 255, 300} {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		got := c.DecodeTXT(c.EncodeTXT(data))
		if size == 0 {
			if len(got) != 0 {
				t.Fatalf("TXT round-trip of empty got %d bytes", len(got))
			}
			continue
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("TXT round-trip mismatch at %d bytes", size)
		}
	}
}
