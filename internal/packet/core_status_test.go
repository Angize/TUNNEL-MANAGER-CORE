package packet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTCPSingleEdgeECHSelfHeal verifies a single fixed-edge ws client (no pool) persists the fresh
// ECH key onto wsECH and writes exactly one ech/self_heal event per rotation to its status file —
// so a single-edge in-band self-heal reaches the panel without spamming on every reconnect.
func TestTCPSingleEdgeECHSelfHeal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	b := &TCP{st: newCoreStatus(path, "ws · edge:443"), wsECH: []byte{0x01}}

	b.noteECHSelfHeal("h.example", []byte{0x02, 0x03}) // first heal: key differs -> persist + emit
	if !bytes.Equal(b.wsECH, []byte{0x02, 0x03}) {
		t.Fatalf("wsECH should be persisted to the fresh key, got %v", b.wsECH)
	}
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "ech" || evs[0].Code != "self_heal" {
		t.Fatalf("want 1 ech/self_heal event, got %+v", evs)
	}
	if evs[0].Detail != "h.example AgM=" { // host + base64(0x02,0x03)
		t.Fatalf("detail should carry host + base64 key, got %q", evs[0].Detail)
	}

	b.noteECHSelfHeal("h.example", []byte{0x02, 0x03}) // same key -> no repeat event
	if evs = readEvents(t, path); len(evs) != 1 {
		t.Fatalf("repeat with an unchanged key must be silent; got %d events", len(evs))
	}

	b.noteECHSelfHeal("h.example", []byte{0x09}) // rotated key -> emit again
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("a rotated key should emit again; got %d events", len(evs))
	}
}

// TestCoreStatusEventPairing verifies the datagram self-heal event contract: the initial connect is
// silent (no spurious "reconnect"), a stale-detect emits one "down", and only then does a connect
// emit a "reconnect" — and the status file is written with a monotonic seq the panel consumes once.
func TestCoreStatusEventPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	s := newCoreStatus(path, "udp · 1.2.3.4:443")

	// First connect at startup must NOT be logged as a self-heal.
	s.reconnected("udp")
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("initial connect should be silent; got %d events: %+v", len(got), got)
	}

	// A stale-detect emits exactly one down.
	s.down("stale", "udp")
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "down" || evs[0].Code != "stale" {
		t.Fatalf("after down: want 1 down/stale, got %+v", evs)
	}

	// The recovery that follows emits one up/reconnect.
	s.reconnected("udp")
	evs = readEvents(t, path)
	if len(evs) != 2 || evs[1].Kind != "up" || evs[1].Code != "reconnect" {
		t.Fatalf("after recovery: want down then up/reconnect, got %+v", evs)
	}
	if evs[0].Seq >= evs[1].Seq {
		t.Fatalf("seq must be monotonic: %d then %d", evs[0].Seq, evs[1].Seq)
	}

	// A second recovery with no intervening down must be silent (no dangling pair).
	s.reconnected("udp")
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("recovery without a pending down must be silent; got %d events", len(evs))
	}

	// A nil writer (server side / status off) is a safe no-op.
	var off *coreStatus
	off.down("stale", "udp")
	off.reconnected("udp")
	off.event("down", "stale", "udp")
}

// TestHBPeriodTracksDeadWindow pins the rule that keeps a healthy tunnel out of the red: hb is a
// TIMESTAMP, so the publish period must stay a fraction of the window the reader ages it against.
//
// The worst case is the tightest window the config allows — dead_after clamped to 2×keepalive — where a
// perfectly healthy carrier's newest frame is already up to 1.3×keepalive old (the keepalive jitter
// ceiling) when it is read. The old fixed 5s period added a whole 5s on top of that and crossed dw.
func TestHBPeriodTracksDeadWindow(t *testing.T) {
	for _, c := range []struct {
		name string
		dw   int64
		want time.Duration
	}{
		{"the default 30s window keeps the 5s ceiling", 30, 5 * time.Second},
		{"a window of exactly 20s still keeps it", 20, 5 * time.Second},
		{"the reported flicker case (keepalive 5 + dead_after 10)", 10, 2500 * time.Millisecond},
		{"a tight window floors at one second, not below", 3, time.Second},
		{"no window resolved keeps the plain ceiling", 0, 5 * time.Second},
	} {
		if got := hbPeriod(c.dw); got != c.want {
			t.Errorf("%s: hbPeriod(%d) = %v, want %v", c.name, c.dw, got, c.want)
		}
	}

	// The property the numbers exist for: publish lag + the oldest a healthy keepalive can be must stay
	// inside the window, for every window a carrier can resolve to. dw==2×keepalive is the tightest legal
	// pairing (deadWindow clamps there). Below dw=3 the jitter ceiling alone (1.3×keepalive) all but fills
	// the window, so the carrier self-heals on its own timing and no publisher can help; the smallest
	// window the shipped knobs can even produce is far above that (dead_after starts at 10).
	for dw := int64(3); dw <= 600; dw++ {
		keepalive := float64(dw) / 2
		oldest := 1.3*keepalive + hbPeriod(dw).Seconds()
		if oldest >= float64(dw) {
			t.Fatalf("dw=%ds: a healthy carrier publishes an age of %.2fs against a %ds window — it reads dead", dw, oldest, dw)
		}
	}
}

func readEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var st struct {
		Events []coreEvent `json:"events"`
	}
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return st.Events
}
