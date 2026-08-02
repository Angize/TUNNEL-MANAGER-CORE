package dnstun

import (
	"errors"
	"testing"
)

// TestBareZoneIsNotAPoll is the regression test for the downstream drain. The delegated zone is PUBLIC —
// it has to be, or resolvers could not reach the server — and DecodeName answered a bare `dig TXT <zone>`
// exactly as it answered a real poll, so the reply path took a datagram off the server->client queue.
// Our client's EncodeName ALWAYS prepends a nonce label, so a bare zone cannot be our client.
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

	// A payload-free POLL must keep working — it is how the client fetches downstream data with
	// nothing to send, so breaking it would break every idle tunnel.
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

	// And a real data-carrying query still round-trips.
	want := []byte("hello upstream")
	n, err := c.EncodeName(want, "abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.DecodeName(n)
	if err != nil || string(got) != string(want) {
		t.Fatalf("round trip: got (%q, %v), want %q", got, err, want)
	}

	// A name outside the zone is still its own, different error — the bare-zone sentinel must not
	// swallow the case the server drops entirely.
	if _, err := c.DecodeName("other.example.org."); errors.Is(err, ErrBareZone) || err == nil {
		t.Fatalf("a name outside the zone returned %v; want the out-of-zone error", err)
	}
}
