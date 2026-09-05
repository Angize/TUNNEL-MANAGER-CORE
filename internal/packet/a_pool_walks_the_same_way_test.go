package packet

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
// The pools themselves are still two implementations -- PeerPool over one axis, wsPool over two --
// and unifying them is a separate job. What is unified here is the RULES they were disagreeing on:
// where a failed walk lands, when the operator is told rotation has stopped, and what a manual jump
// does to the rotation clock.

// The walk after a verdict may not hand back an endpoint it has just condemned. The direct pools
// walked healthy -> due -> best; the edge pool did a bare (i+1)%n and reported whatever landed under
// the cursor, which could be the edge that had just burned. The cursor self-corrects on the next
// read, so the tunnel did not dial it -- but the rotation event named it, and that is the line the
// operator reads to find out where their tunnel went.
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
		p := newWSPool([]string{"a", "b", "c"}, snis("x"))
		p.markSuspect("ip", "b", "test")
		got := p.advanceIP()
		if got == "" {
			t.Fatal("the walk did not move at all")
		}
		if got == "b" {
			t.Error("the walk reported b, which is burned — the operator reads this line to find " +
				"out where the tunnel went, and the tunnel is not there")
		}
	})

	t.Run("edge pool, domains", func(t *testing.T) {
		p := newWSPool([]string{"a"}, snis("x", "y", "z"))
		p.markSuspect("sni", "y", "test")
		if got := p.advanceSNI(); got == "y" {
			t.Error("the domain walk reported y, which is burned")
		}
	})

	t.Run("and nothing to move to is reported as not moving", func(t *testing.T) {
		p := newWSPool([]string{"a", "b"}, snis("x"))
		p.markSuspect("ip", "b", "test")
		p.markSuspect("ip", "a", "test")
		p.mu.Lock()
		burned := len(p.ipHealth.recs)
		p.mu.Unlock()
		if burned != 2 {
			t.Fatalf("setup: %d burned, want 2", burned)
		}
		if got := p.advanceIP(); got != "" && got != "b" {
			t.Errorf("with both edges burned the walk reported %q; it may take the least-bad one or "+
				"stay, but it may not invent a third", got)
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
		b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
		p.markSuspect("ip", "e1", "test")
		got := seen(b.readStatus(t).Events, "degraded")
		if len(got) != 1 || !strings.HasPrefix(got[0], "ip:") {
			t.Fatalf("edge degraded events: %v", got)
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

// The clock. `jumped()` restarts c.rotateAt, which only raw and udp ever read -- the TCP family
// keeps its own deadline in b.rotAt and nothing was resetting it. Land on edge B with two seconds
// left of a ten-minute period and B was rotated away two seconds later.
func TestAJumpRestartsWhicheverClockTheCarrierKeeps(t *testing.T) {
	const period = 10 * time.Minute

	t.Run("Run wires it, so the cases below are not testing a hook only this file installs",
		func(t *testing.T) {
			run := funcBody(t, "tcp.go", "func (b *TCP) Run()")
			if !strings.Contains(run, "b.armRotationClock()") {
				t.Fatal("TCP.Run does not arm the rotation clock, so nothing in production resets it")
			}
		})

	t.Run("the tcp family", func(t *testing.T) {
		b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
		b.rotate = period
		b.rc.bindEdges(p)
		b.armRotationClock()

		b.rotateFrom(2 * time.Second)
		if left := b.rotateIn(period); left > 5*time.Second {
			t.Fatalf("setup: %v left, want about 2s", left)
		}

		if !b.operatorJump(t, "ip", "e2") {
			t.Fatal("the jump was not applied")
		}
		left := b.rotateIn(period)
		if left < period-time.Minute {
			t.Fatalf("only %v of the %v period is left after the jump — the operator's pick is "+
				"rotated away almost immediately", left.Round(time.Second), period)
		}
	})

	t.Run("raw and udp, which keep the controller's clock", func(t *testing.T) {
		dst := NewPeerPool([]string{"d1", "d2", "d3"}, period)
		rc := newRotationController(dst, nil)
		rc.attachStatus(newCoreStatus(t.TempDir()+"/core.json", ""))
		rc.mu.Lock()
		rc.rotateAt = time.Now().Add(2 * time.Second)
		rc.mu.Unlock()

		writeFileAtomic(rc.selbox, []byte(`{"kind":"dst","key":"d3"}`), 0o644)
		if !rc.poll(func(bool) {}, func(bool) {}, nil, func() int64 { return 0 }) {
			t.Fatal("the jump was not applied")
		}
		rc.mu.Lock()
		left := time.Until(rc.rotateAt)
		rc.mu.Unlock()
		if left < period-time.Minute {
			t.Fatalf("only %v of the %v period is left after the jump", left.Round(time.Second), period)
		}
	})

	t.Run("a carrier with no rotation is not handed a deadline of zero", func(t *testing.T) {
		b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
		b.rc.bindEdges(p)
		b.armRotationClock()
		if !b.operatorJump(t, "ip", "e2") {
			t.Fatal("the jump was not applied")
		}
		if at := b.rotAt.Load(); at != 0 {
			t.Errorf("rotation is off, yet the jump armed a deadline (%d) — the next rotateIn would "+
				"fire in a millisecond", at)
		}
	})
}
