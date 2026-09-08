package packet

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func funcBody(t *testing.T, file, sig string) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(here), file))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, sig)
	if i < 0 {
		t.Fatalf("%s: %s not found", file, sig)
	}
	for k := i; k+2 < len(s); k++ {
		if s[k] == 10 && s[k+1] == 125 && s[k+2] == 10 {
			return s[i : k+1]
		}
	}
	return s[i:]
}

// Three things every carrier with a pool does, which three carriers were doing differently.
//
// The edge carriers stand on the same PeerPool as the direct ones now -- one pool per axis, the edge
// IPs low and the SNI hosts high -- so the two implementations of a walk have become one. What is
// asserted here are the RULES they used to disagree on: where a failed walk lands, when the operator
// is told rotation has stopped, and what a manual jump does to the rotation clock.

// The walk after a verdict may not hand back an endpoint it has just condemned. The direct pools
// walked healthy -> due -> best; the edge pool did a bare (i+1)%n and reported whatever landed under
// the cursor, which could be the edge that had just burned. Both axes of an edge carrier are
// PeerPools now, so both walk in that order -- and the rotation event, the line the operator reads
// to find out where their tunnel went, names somewhere the tunnel can actually be.
func TestAFailedWalkNeverLandsOnWhatItJustBurned(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b", "c"}, 0)
		p.markSuspect("b", "test")
		p.mu.Lock()
		p.cur = 0
		p.mu.Unlock()
		got, moved := p.fail("tun-probe")
		if !moved {
			t.Fatal("the walk did not move at all")
		}
		if got == "b" {
			t.Error("the walk landed on b, which is burned")
		}
	})

	t.Run("edge pool", func(t *testing.T) {
		b := edgeTCP([]string{"a", "b", "c"}, snis("x"), 0)
		b.pp.markSuspect("b", "test")
		got, moved := b.pp.fail("tun-probe")
		if !moved {
			t.Fatal("the walk did not move at all")
		}
		if got == "b" {
			t.Error("the walk reported b, which is burned — the operator reads this line to find " +
				"out where the tunnel went, and the tunnel is not there")
		}
	})

	t.Run("edge pool, domains", func(t *testing.T) {
		b := edgeTCP([]string{"a"}, snis("x", "y", "z"), 0)
		b.sp.markSuspect("y", "test")
		if got, _ := b.sp.fail("tun-probe"); got == "y" {
			t.Error("the domain walk reported y, which is burned")
		}
	})

	// With every edge condemned there is no healthy and no due entry left, so the walk falls through to
	// the least-bad one -- earliest retest wins, NOT the next index. Laid out so those two disagree:
	// b is on its second strike (retest 3400) while c is on its first (2200), so the answer is c even
	// though b is the one the cursor would reach by counting.
	t.Run("with every edge burned the walk takes the least-bad, not the next in line", func(t *testing.T) {
		b := edgeTCP([]string{"a", "b", "c"}, snis("x"), 0)
		clk := int64(1000)
		b.pp.now = func() int64 { return clk }

		b.pp.markSuspect("b", "test")
		clk = 1600
		b.pp.markSuspect("b", "test")
		b.pp.markSuspect("c", "test")
		clk = 1700

		b.pp.mu.Lock()
		bn, cn := b.pp.health.rec("b").nextRetest, b.pp.health.rec("c").nextRetest
		b.pp.mu.Unlock()
		if !(bn > cn) {
			t.Fatalf("setup: b retests at %d and c at %d; c must be the least-bad one", bn, cn)
		}

		got, _ := b.pp.fail("tun-probe")
		if got != "c" {
			t.Errorf("with every edge burned the walk reported %q, want \"c\" — b is next by index but "+
				"retests at %d, c at %d, and the walk owes the operator the one that comes back soonest",
				got, bn, cn)
		}
	})
}

// «چرخش متوقف شد — فقط یک مسیر مانده» was an edge-pool event only. A direct tunnel with three
// destination IPs and two of them burned rotates nowhere and said nothing at all. Both pools report
// it now, and both name the axis so the panel can say WHICH one stopped.
func TestBothPoolsSayWhenRotationHasStopped(t *testing.T) {
	seen := func(evs []coreEvent, code string) []string {
		var out []string
		for _, e := range evs {
			if e.Kind == "pool" && e.Code == code {
				out = append(out, e.Detail)
			}
		}
		return out
	}

	t.Run("direct pool", func(t *testing.T) {
		b, pp, _ := peerCarrier(t, []string{"a", "b", "c"}, nil)
		pp.markSuspect("a", "tun-probe")
		if got := seen(b.readStatus(t).Events, "degraded"); len(got) != 0 {
			t.Fatalf("two of three left is still a rotation: %v", got)
		}
		pp.markSuspect("b", "tun-probe")
		got := seen(b.readStatus(t).Events, "degraded")
		if len(got) != 1 {
			t.Fatalf("one of three left and the operator was told %d times: %v", len(got), got)
		}
		if !strings.HasPrefix(got[0], "dst:") {
			t.Errorf("the event does not name the axis (%q), so the panel cannot say WHICH rotation "+
				"stopped -- it would call a destination pool a CDN edge", got[0])
		}
		pp.markSuspect("c", "tun-probe")
		if got := seen(b.readStatus(t).Events, "degraded"); len(got) != 1 {
			t.Errorf("the warning repeated: %v", got)
		}
		pp.clearBurn("b")
		if got := seen(b.readStatus(t).Events, "restored"); len(got) != 0 {
			t.Errorf("one of three back is still not a rotation, yet it was reported: %v", got)
		}
		pp.clearBurn("c")
		if got := seen(b.readStatus(t).Events, "restored"); len(got) != 1 {
			t.Errorf("two of three back IS a rotation again, and it was not reported: %v", got)
		}
	})

	t.Run("a source pool reports on its own axis", func(t *testing.T) {
		b, _, sp := peerCarrier(t, []string{"d1", "d2"}, []string{"s1", "s2", "s3"})
		sp.markSuspect("s1", "tun-probe")
		sp.markSuspect("s2", "tun-probe")
		got := seen(b.readStatus(t).Events, "degraded")
		if len(got) != 1 || !strings.HasPrefix(got[0], "src:") {
			t.Fatalf("the source axis did not report itself: %v", got)
		}
	})

	t.Run("edge pool, unchanged, and now it names its axis too", func(t *testing.T) {
		b, pp, _ := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
		pp.markSuspect("e1", "test")
		got := seen(b.readStatus(t).Events, "degraded")
		if len(got) != 1 || !strings.HasPrefix(got[0], "ip:") {
			t.Fatalf("edge degraded events: %v", got)
		}
	})

	t.Run("the sni axis of an edge carrier reports on its own axis too", func(t *testing.T) {
		b, _, sp := edgeCarrier(t, []string{"e1"}, snis("x", "y"))
		sp.markSuspect("x", "test")
		got := seen(b.readStatus(t).Events, "degraded")
		if len(got) != 1 || !strings.HasPrefix(got[0], "sni:") {
			t.Fatalf("the sni axis did not report itself: %v", got)
		}
	})

	t.Run("a one-entry pool never says rotation stopped, because it never rotated", func(t *testing.T) {
		b, pp, _ := peerCarrier(t, []string{"only"}, nil)
		pp.markSuspect("only", "tun-probe")
		if got := seen(b.readStatus(t).Events, "degraded"); len(got) != 0 {
			t.Errorf("a single-endpoint tunnel was told its rotation stopped: %v", got)
		}
	})

	t.Run("pulling a retest forward reports the recovery", func(t *testing.T) {
		b, pp, _ := peerCarrier(t, []string{"a", "b", "c"}, nil)
		pp.markSuspect("a", "tun-probe")
		pp.markSuspect("b", "tun-probe")
		if got := seen(b.readStatus(t).Events, "degraded"); len(got) != 1 {
			t.Fatalf("setup: %v", got)
		}
		pp.retestNow("a")
		if got := seen(b.readStatus(t).Events, "restored"); len(got) != 1 {
			t.Errorf("an endpoint pulled back into the rotation did not report the recovery: %v", got)
		}
	})
}
