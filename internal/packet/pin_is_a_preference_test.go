package packet

import "testing"

// The rule this file pins, on all three shapes: a pin is the operator saying "go here", not "stay here
// whatever happens". The first verdict or refused attempt against it ends it, and the same round burns
// and walks as if the pin had never been there.

func TestPinEndsOnTheFirstSecondOpinion_Direct(t *testing.T) {
	dst := NewPeerPool([]string{"d1", "d2"}, 0)
	src := NewPeerPool([]string{"s1", "s2"}, 0)
	rc := newRotationController(dst, src)
	if !dst.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	moved := 0
	rot := func(bool) { moved++ }

	rc.fail(rot, rot)
	if dst.isPinned() {
		t.Fatal("the pin survived its first proven-dead verdict")
	}
	if moved == 0 {
		t.Fatal("the pin released but the pool did not move off the blocked endpoint in the same round")
	}
}

func TestPinEndsOnTheFirstSecondOpinion_TCP(t *testing.T) {
	b, pp, _ := peerCarrier(t, []string{"d1", "d2"}, []string{"s1", "s2"})
	if !pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	if !tcpWalk(b) {
		t.Fatal("the first verdict under a pin must release it AND burn — absorbing it leaves the " +
			"tunnel forced onto an endpoint the probe has already condemned")
	}
	if pp.isPinned() {
		t.Fatal("the pin still freezes failover after a proven-dead verdict")
	}
}

func TestPinEndsOnTheFirstSecondOpinion_CDN(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("s1", "s2"))
	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not pin")
	}
	ip, sni, _ := p.current()
	b.pretendConnected(sni.host, ip)

	if !b.tunFail(t, sni.host, ip) {
		t.Fatal("the first verdict under a pin must release it and burn")
	}
	if p.isPinned() {
		t.Fatal("the pin still holds the edge after a proven-dead verdict")
	}
	if p.sniHealth.healthy(sni.host) {
		t.Fatal("the pin released but nothing was burned — the same round must do both")
	}
}

func TestAFreshPinIsNotBoundByTheLastOne(t *testing.T) {
	b, pp, _ := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})

	if !pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	tcpWalk(b)
	if pp.isPinned() {
		t.Fatal("setup: the first pin should already be gone")
	}

	if !pp.selectEntry("d3") {
		t.Fatal("could not re-pin")
	}
	if !pp.isPinned() {
		t.Fatal("the fresh pin was born released — it inherited the earlier pin's state")
	}
}

func TestAPinEndsOnEvidenceNeverOnAClock(t *testing.T) {
	t.Run("it lands", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		if !p.selectEntry("b") || !p.isPinned() {
			t.Fatal("could not pin")
		}
		p.pinLandedOn("b")
		if p.isPinned() {
			t.Fatal("a landed pin must release at once")
		}
	})
	t.Run("it cannot land", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		if !p.selectEntry("b") || !p.isPinned() {
			t.Fatal("could not pin")
		}
		p.pinCannotLand("a")
		if !p.isPinned() {
			t.Fatal("a refusal on a DIFFERENT endpoint released the pin")
		}
		p.pinCannotLand("b")
		if p.isPinned() {
			t.Fatal("the pin survived the first refused attempt on the pinned endpoint")
		}
	})
	t.Run("time alone does nothing", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		clk := int64(1000)
		p.now = func() int64 { return clk }
		if !p.selectEntry("b") {
			t.Fatal("could not pin")
		}
		clk += 86400
		if !p.isPinned() {
			t.Fatal("the clock released a pin that nothing had disproven")
		}
	})
}

func TestAHealthySessionEndsTheRound(t *testing.T) {
	t.Run("the direct pool's lap", func(t *testing.T) {
		b, pp, _ := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})
		if !pp.selectEntry("d2") {
			t.Fatal("could not pin")
		}
		tcpWalk(b)
		b.rc.od.rot = 3
		b.endRound()
		if got := b.rc.od.rot; got != 0 {
			t.Fatalf("the lap survived a healthy session (rot=%d)", got)
		}
	})
	t.Run("the edge pool's lap", func(t *testing.T) {
		b, _ := edgeCarrier(t, []string{"e1", "e2"}, snis("s1", "s2", "s3"))
		b.rc.od.rot = 2
		b.endRound()
		if got := b.rc.od.rot; got != 0 {
			t.Fatalf("the edge pool's half-walked lap survived a healthy session (rot=%d) — the next "+
				"outage would convict the edge after one verdict", got)
		}
	})
}
