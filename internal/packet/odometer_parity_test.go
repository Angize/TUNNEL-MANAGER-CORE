package packet

import (
	"fmt"
	"path/filepath"
	"testing"
)

type odoTrace struct {
	destBurns  []string
	srcMovedOn []int
}

func (o odoTrace) String() string {
	return fmt.Sprintf("burns=%v sourceMovesOnRounds=%v", o.destBurns, o.srcMovedOn)
}

func burnedSet(p *PeerPool) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, a := range p.addrs {
		if !p.health.healthy(a) {
			out = append(out, a)
		}
	}
	return out
}

func runControllerOdometer(t *testing.T, dests, srcs []string, rounds int) odoTrace {
	t.Helper()
	dir := t.TempDir()
	dst := NewPeerPool(dests, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool(srcs, 0, filepath.Join(dir, "s.json"))
	c := newRotationController(dst, src)

	var tr odoTrace
	for r := 1; r <= rounds; r++ {
		before := dst.current()

		srcBefore := src.current()
		c.fail(
			func(proactive bool) { dst.fail() },
			func(proactive bool) { src.fail() },
		)
		if len(burnedSet(dst)) > 0 {
			tr.destBurns = append(tr.destBurns, before)
		}
		if src.current() != srcBefore {
			tr.srcMovedOn = append(tr.srcMovedOn, r)
		}
	}
	return tr
}

func runTCPOdometer(t *testing.T, dests, srcs []string, rounds int) odoTrace {
	t.Helper()
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool(dests, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool(srcs, 0, filepath.Join(dir, "s.json")),
	}
	var tr odoTrace
	for r := 1; r <= rounds; r++ {
		before := b.pp.current()
		srcBefore := b.sp.current()
		b.burnAdvance(true)
		if len(burnedSet(b.pp)) > 0 {
			tr.destBurns = append(tr.destBurns, before)
		}
		if b.sp.current() != srcBefore {
			tr.srcMovedOn = append(tr.srcMovedOn, r)
		}
	}
	return tr
}

func TestTheTwoDirectOdometersAgree(t *testing.T) {
	shapes := []struct{ d, s int }{
		{1, 1}, {1, 2}, {1, 3}, {2, 1}, {2, 2}, {2, 3}, {3, 1}, {3, 2}, {3, 3}, {4, 2},
	}
	for _, sh := range shapes {
		sh := sh
		t.Run(fmt.Sprintf("%ddest_%dsrc", sh.d, sh.s), func(t *testing.T) {
			dests := make([]string, sh.d)
			for i := range dests {
				dests[i] = fmt.Sprintf("d%d", i+1)
			}
			srcs := make([]string, sh.s)
			for i := range srcs {
				srcs[i] = fmt.Sprintf("s%d", i+1)
			}
			ctl := runControllerOdometer(t, dests, srcs, 8)
			tcp := runTCPOdometer(t, dests, srcs, 8)

			if len(ctl.srcMovedOn) != len(tcp.srcMovedOn) {
				t.Fatalf("the source is walked on different rounds:\n  udp/raw/flux: %v\n  tcp:          %v\n"+
					"one carrier blames the source for a lap the other says never completed", ctl, tcp)
			}
			for i := range ctl.srcMovedOn {
				if ctl.srcMovedOn[i] != tcp.srcMovedOn[i] {
					t.Fatalf("the source is walked on different rounds:\n  udp/raw/flux: %v\n  tcp:          %v", ctl, tcp)
				}
			}
			if len(ctl.destBurns) != len(tcp.destBurns) {
				t.Fatalf("a different number of destinations was condemned:\n  udp/raw/flux: %v\n  tcp: %v", ctl, tcp)
			}
		})
	}
}

func TestBothDirectOdometersAbsorbTheSamePin(t *testing.T) {
	dests := []string{"d1", "d2", "d3"}

	dir := t.TempDir()
	dst := NewPeerPool(dests, 0, filepath.Join(dir, "d.json"))
	c := newRotationController(dst, nil)
	dst.selectEntry("d2")
	ctlReleasedOn := 0
	for r := 1; r <= 10 && ctlReleasedOn == 0; r++ {
		c.fail(func(bool) { dst.fail() }, nil)
		if !dst.isPinned() {
			ctlReleasedOn = r
		}
	}

	dir2 := t.TempDir()
	b := &TCP{pp: NewPeerPool(dests, 0, filepath.Join(dir2, "d.json"))}
	b.pp.selectEntry("d2")
	tcpReleasedOn := 0
	for r := 1; r <= 10 && tcpReleasedOn == 0; r++ {
		b.burnAdvance(true)
		if !b.pp.isPinned() {
			tcpReleasedOn = r
		}
	}

	if ctlReleasedOn != tcpReleasedOn {
		t.Fatalf("the pin survives a different number of verdicts per carrier: udp/raw/flux released on "+
			"round %d, tcp on round %d — the same operator pick is overridden at different speeds",
			ctlReleasedOn, tcpReleasedOn)
	}
	if ctlReleasedOn != pinFailRelease {
		t.Fatalf("the pin released on round %d, want pinFailRelease=%d", ctlReleasedOn, pinFailRelease)
	}
}

func TestNoDirectCarrierBurnsWithNowhereToGo(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, dst *PeerPool)
	}{
		{"udp/raw/flux", func(t *testing.T, dst *PeerPool) {
			c := newRotationController(dst, nil)
			for i := 0; i < 5; i++ {
				c.fail(func(bool) { dst.fail() }, nil)
			}
		}},
		{"tcp", func(t *testing.T, dst *PeerPool) {
			b := &TCP{pp: dst}
			for i := 0; i < 5; i++ {
				b.burnAdvance(true)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := NewPeerPool([]string{"only"}, 0, filepath.Join(t.TempDir(), "d.json"))
			tc.run(t, dst)
			if got := burnedSet(dst); len(got) > 0 {
				t.Fatalf("the only destination was condemned (%v) though nothing varied and there is "+
					"nowhere to rotate to", got)
			}
		})
	}
}
