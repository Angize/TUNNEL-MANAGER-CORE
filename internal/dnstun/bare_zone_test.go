package dnstun

import (
	"errors"
	"testing"
)

func TestBareZoneIsNotAPoll(t *testing.T) {
	c, err := NewCodec("t.example.com")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"t.example.com", "t.example.com.", "T.Example.COM."} {
		got, err := c.DecodeName(name)
		if !errors.Is(err, ErrBareZone) {
			t.Fatalf("DecodeName(%q) = (%v, %v); a bare-zone query must be distinguishable from a poll, "+
				"or answering it costs the real client a downstream datagram", name, got, err)
		}
		if got != nil {
			t.Fatalf("DecodeName(%q) returned data %v for a bare zone", name, got)
		}
	}

	poll, err := c.EncodeName(nil, "abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.DecodeName(poll)
	if err != nil {
		t.Fatalf("a nonce-only poll %q was rejected: %v", poll, err)
	}
	if len(data) != 0 {
		t.Fatalf("a poll carried %d bytes of upstream data, want 0", len(data))
	}

	want := []byte("hello upstream")
	n, err := c.EncodeName(want, "abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecodeName(n)
	if err != nil || string(got) != string(want) {
		t.Fatalf("round trip: got (%q, %v), want %q", got, err, want)
	}

	if _, err := c.DecodeName("other.example.org."); errors.Is(err, ErrBareZone) || err == nil {
		t.Fatalf("a name outside the zone returned %v; want the out-of-zone error", err)
	}
}
