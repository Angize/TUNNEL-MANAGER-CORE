package packet

import (
	"testing"
	"time"
)

// TestFakeModeHonoursSplitTTL is the regression test for split_ttl being live everywhere except the
// packet.
//
// In user terms: pick sni_mode=fake in the panel and it shows the «TTLِ سگمنتِ سرْ (split_ttl)» box.
// The value is validated, stored, sent to the node, sent to the core, and printed at startup as
// ttl=N — and then the fake path stamped a hardcoded 64 on the decoy. Every layer agreed on a number
// that never reached the wire.
func TestFakeModeHonoursSplitTTL(t *testing.T) {
	// The operator's value wins.
	f := newFragConn(nil, "example.com", 0, sniFakeMode, 5, nil)
	if got := f.fakeSegTTL(); got != 5 {
		t.Fatalf("decoy TTL = %d, want the configured 5 — split_ttl is accepted, shipped and logged, "+
			"so it has to reach the packet", got)
	}
	// Unset keeps fake mode's own default, which is deliberately NOT the low disorder TTL: the decoy
	// is killed at the server by its bad checksum and has to survive long enough to reach the DPI.
	f = newFragConn(nil, "example.com", 0, sniFakeMode, 0, nil)
	if got := f.fakeSegTTL(); got != fakeTTL {
		t.Fatalf("unset split_ttl gave TTL %d, want fake mode's default %d", got, fakeTTL)
	}
	if fakeTTL == disorderTTL {
		t.Fatalf("fake mode's default TTL must not be the low disorder TTL — the decoy would expire "+
			"before the DPI it exists to feed (both are %d)", fakeTTL)
	}
	// And it is plumbed from the carrier, not just settable by hand.
	b := &TCP{isClient: true, ws: true}
	if !b.SetSNISplit(true, 0, sniFakeMode, 7) {
		t.Fatal("a ws carrier must accept sni_split")
	}
	if got := b.fragWrap(nil, "example.com").(*fragConn).fakeSegTTL(); got != 7 {
		t.Fatalf("the carrier plumbed TTL %d into the conn, want 7", got)
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
