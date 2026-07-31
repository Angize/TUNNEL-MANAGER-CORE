package packet

import (
	"testing"
	"time"
)

// TestFakeModeIgnoresSplitTTL pins that the fake decoy's TTL is NOT the disorder knob.
//
// This test previously asserted the opposite, and asserting the opposite is what shipped the bug.
// The two modes want opposite values out of one stored number: disorder needs it LOW (default 4) so
// the head segment expires before the server, fake needs it HIGH because its decoy is killed at the
// server by a bad checksum and has to reach the on-path DPI first. The panel keeps ONE input for
// both, so a tunnel that stored 4 for disorder and then switched to fake got a decoy that died en
// route — the strongest SNI mode silently reduced to an expensive no-op.
//
// In user terms: picking «ClientHelloِ جعلی» must behave the same whatever number is sitting in the
// TTL box from a previous mode.
func TestFakeModeIgnoresSplitTTL(t *testing.T) {
	for _, ttl := range []int{0, 1, 4, 5, 64, 255} {
		f := newFragConn(nil, "example.com", 0, sniFakeMode, ttl, nil)
		if got := f.fakeSegTTL(); got != fakeTTL {
			t.Fatalf("split_ttl=%d gave the decoy TTL %d, want fake mode's own %d — a stored disorder "+
				"value must not reach the decoy", ttl, got, fakeTTL)
		}
	}
	if fakeTTL <= disorderTTL {
		t.Fatalf("fake mode's TTL (%d) must be well above the disorder TTL (%d) — the decoy has to "+
			"outlive the hops disorder's head segment is meant to die within", fakeTTL, disorderTTL)
	}
	// disorder still reads it: the knob is not dead, it just belongs to one mode.
	d := newFragConn(nil, "example.com", 0, sniDisorderMode, 5, nil)
	if d.ttl != 5 {
		t.Fatalf("disorder must still carry the operator's split_ttl, got %d", d.ttl)
	}
	// And the carrier plumbs it through unchanged, so this is the whole path and not a helper.
	b := &TCP{isClient: true, ws: true}
	if !b.SetSNISplit(true, 0, sniFakeMode, 4) {
		t.Fatal("a ws carrier must accept sni_split")
	}
	if got := b.fragWrap(nil, "example.com").(*fragConn).fakeSegTTL(); got != fakeTTL {
		t.Fatalf("through the carrier, a stored split_ttl=4 produced decoy TTL %d, want %d", got, fakeTTL)
	}
}

// TestSetSNISplitReportsWhetherItApplied pins the seam the startup log depends on. *TCP implements
// SetSNISplit for transport=tcp as well as ws, and on tcp it discards the setting — so main could
// not tell an applied knob from a discarded one and printed "SNI fragmentation on" either way.
func TestSetSNISplitReportsWhetherItApplied(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    *TCP
		want bool
	}{
		{"ws client", &TCP{isClient: true, ws: true}, true},
		{"plain tcp client", &TCP{isClient: true}, false},
		{"ws server", &TCP{ws: true}, false},
	} {
		if got := tc.b.SetSNISplit(true, 0, sniSplitMode, 0); got != tc.want {
			t.Fatalf("%s: SetSNISplit reported %v, want %v", tc.name, got, tc.want)
		}
		if tc.b.sniSplit != tc.want {
			t.Fatalf("%s: reported %v but stored sniSplit=%v — the report must match what was applied",
				tc.name, tc.want, tc.b.sniSplit)
		}
	}
}

// TestServerHonoursDeadAfter is the carrier half of the dead_after_secs finding: the SERVER's
// read deadline must move when the knob is set, because on tcp/ws that window IS the dead-detection
// window and the panel writes the setting onto both ends of the tunnel.
func TestServerHonoursDeadAfter(t *testing.T) {
	const keepalive = 10 * time.Second
	srv := &TCP{keepalive: keepalive, idle: idleFor(keepalive)}
	def := srv.idle
	srv.SetDeadAfter(40)
	if srv.idle == def {
		t.Fatalf("a server's dead window stayed at its default %v — half the tunnel would self-heal at "+
			"the configured speed and half would not", def)
	}
	if srv.idle != 40*time.Second {
		t.Fatalf("server dead window = %v, want 40s", srv.idle)
	}
	// The floor still applies on a server exactly as on a client: a value under 2×keepalive would
	// reap a healthy link between pongs.
	srv = &TCP{keepalive: keepalive, idle: idleFor(keepalive)}
	srv.SetDeadAfter(5)
	if srv.idle != 2*keepalive {
		t.Fatalf("server dead window = %v, want the 2×keepalive floor %v", srv.idle, 2*keepalive)
	}
}
