package packet

import (
	"testing"
)

func TestAProactiveRotationHandsADueEdgeLiveTraffic(t *testing.T) {
	b := edgeTCP([]string{"e1", "e2"}, snis("x"), 0)
	clk := int64(1000)
	b.pp.now = func() int64 { return clk }
	b.sp.now = func() int64 { return clk }
	if ip := b.pp.current(); ip != "e1" {
		t.Fatalf("setup: the cursor starts on %q, want e1", ip)
	}
	b.pp.markSuspect("e2", "tun-probe")

	if b.walkEdge() {
		t.Fatal("e2 is still waiting out its backoff, so there is nowhere to go — reporting a move tears " +
			"the live connection down every rotation tick for nothing")
	}
	if ip := b.pp.current(); ip != "e1" {
		t.Fatalf("the walk moved onto a waiting edge: %q", ip)
	}

	clk += suspectBackoff[0]
	if !b.walkEdge() {
		t.Fatal("e2 came due and the rotation still would not go there — a burned edge that is never " +
			"selected can never be proven to have recovered, so it stays condemned forever")
	}
	ip, _, ok := b.edgeCombo()
	if !ok || ip != "e2" {
		t.Fatalf("the rotation stepped onto e2 and the combo resolved back to %q — the walk must not "+
			"re-select past the combination it deliberately moved onto", ip)
	}

	if ip2, _, _ := b.edgeCombo(); ip2 != "e2" {
		t.Fatalf("the second ask gave %q — the commitment did not hold for the life of the attempt", ip2)
	}
}

func TestOnlyTheTunProbeEndsTheTry(t *testing.T) {
	t.Run("fail: burned again, and further down the ladder", func(t *testing.T) {
		b, pp, sp := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
		clk := int64(1000)
		pp.now = func() int64 { return clk }
		sp.now = func() int64 { return clk }
		pp.markSuspect("e2", "tun-probe")
		clk += suspectBackoff[0]
		b.walkEdge()
		ip, sni, ok := b.edgeCombo()
		if !ok || ip != "e2" {
			t.Fatalf("setup: the try landed on %q", ip)
		}
		b.pretendConnected(ip, sni.host)
		if !b.tunFail(t, ip, sni.host) {
			t.Fatal("the verdict did nothing")
		}
		pp.mu.Lock()
		due := pp.health.due("e2")
		pp.mu.Unlock()
		if due {
			t.Fatal("e2 is STILL due after failing the try the ladder granted it — every rotation tick " +
				"now returns to a proven-dead edge, drops the tunnel, and walks off it again, forever")
		}
		if got := pp.current(); got != "e1" {
			t.Fatalf("after the verdict the walk stayed on %q", got)
		}
	})

	t.Run("ok: cleared outright, no ladder left to wait out", func(t *testing.T) {
		b := edgeTCP([]string{"e1", "e2"}, snis("x"), 0)
		clk := int64(1000)
		b.pp.now = func() int64 { return clk }
		b.sp.now = func() int64 { return clk }
		b.pp.markSuspect("e2", "tun-probe")
		clk += suspectBackoff[0]
		b.walkEdge()

		if !b.pp.clearBurn("e2") {
			t.Fatal("the tun probe said data crossed and the pool had nothing to clear")
		}
		b.pp.mu.Lock()
		healthy := b.pp.health.healthy("e2")
		b.pp.mu.Unlock()
		if !healthy {
			t.Fatal("data crossed on e2 and it is not healthy — that IS the proof, and there is nothing " +
				"stronger the pool could ever be given")
		}
	})
}

func TestTheLadderDeepensOnTheRetryItsBackoffAllowed(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }
	p.fail("tun-probe")
	p.fail("tun-probe")

	addr := activeOf(p)
	p.mu.Lock()
	before := *p.health.rec(addr)
	p.mu.Unlock()

	p.fail("tun-probe")
	p.mu.Lock()
	held := *p.health.rec(addr)
	p.mu.Unlock()
	if held.fails != before.fails || held.nextRetest != before.nextRetest {
		t.Fatalf("%s is condemned and its backoff has not run out, yet a verdict deepened it anyway "+
			"(%+v -> %+v). At one verdict every three seconds that reaches the six-hour step in under a "+
			"minute, and every number the operator set on the way there means nothing", addr, before, held)
	}

	clk = before.nextRetest
	p.fail("tun-probe")
	p.mu.Lock()
	after := *p.health.rec(addr)
	p.mu.Unlock()
	if after.fails == before.fails && after.nextRetest == before.nextRetest {
		t.Fatalf("%s came due, was handed back, was tried, and failed, and its ladder did not move "+
			"(%+v) — the carrier would retry it at the shortest interval the ladder has, forever", addr, after)
	}
}
