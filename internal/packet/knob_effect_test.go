package packet

import (
	"testing"
	"time"
)

// TestFakeModeIgnoresSplitTTL pins that the fake decoy's TTL is not the disorder knob. The two modes
// want opposite values from one stored number: disorder low so the head expires, fake high so the
// decoy outruns the DPI.
func TestFakeModeIgnoresSplitTTL(t *testing.T) {
	for _, ttl := range []int{0, 1, 4, 5, 64, 255} {
		f := newFragConn(nil, "example.com", 0, sniFakeMode, ttl, false, nil)
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
	d := newFragConn(nil, "example.com", 0, sniDisorderMode, 5, false, nil)
	if d.ttl != 5 {
		t.Fatalf("disorder must still carry the operator's split_ttl, got %d", d.ttl)
	}
	// And the carrier plumbs it through unchanged, so this is the whole path and not a helper.
	b := &TCP{isClient: true, ws: true}
	if !b.SetSNISplit(true, 0, sniFakeMode, 4) {
		t.Fatal("a ws carrier must accept sni_split")
	}
	if got := b.fragWrap(nil, "example.com", nil).(*fragConn).fakeSegTTL(); got != fakeTTL {
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

// TestSetDeadAfterReportsWhetherItWillBeEnforced pins the seam main's startup line depends on.
// dead_after_secs is applied on BOTH roles, which is right — on tcp/ws the window IS the connection's
// read deadline and the server has one too. But the connectionless carriers reap only from a client
// loop, so on their SERVER the value is stored and never read. The carrier is the only thing that knows.
func TestSetDeadAfterReportsWhetherItWillBeEnforced(t *testing.T) {
	const keepalive = 10 * time.Second

	// tcp/ws: BOTH roles enforce it, because b.idle is the read deadline at each end.
	for _, isClient := range []bool{true, false} {
		b := &TCP{keepalive: keepalive, idle: idleFor(keepalive), isClient: isClient}
		if !b.SetDeadAfter(40) {
			t.Fatalf("tcp isClient=%v refused to enforce dead_after_secs, but b.idle is its read deadline", isClient)
		}
		if b.idle != 40*time.Second {
			t.Fatalf("tcp isClient=%v: window = %v, want 40s", isClient, b.idle)
		}
	}

	// udp: the client enforces it via sessionStale; the server has no such loop.
	cli := &UDP{isClient: true}
	if !cli.SetDeadAfter(40) || cli.deadAfterSecs != 40 {
		t.Fatalf("udp client must enforce dead_after_secs (reported %v, stored %d)", cli.SetDeadAfter(40), cli.deadAfterSecs)
	}
	srv := &UDP{}
	if srv.SetDeadAfter(40) {
		t.Fatal("a udp SERVER reported it would enforce dead_after_secs — clientLoop, the only reader, never starts there")
	}
	if srv.deadAfterSecs != 40 {
		t.Fatalf("the value must still be stored (got %d): only the CLAIM changes", srv.deadAfterSecs)
	}

	// 0 is not an application on any carrier.
	if (&UDP{isClient: true}).SetDeadAfter(0) || (&TCP{keepalive: keepalive}).SetDeadAfter(0) {
		t.Fatal("dead_after_secs=0 leaves the default formula alone and must not report an application")
	}
}
