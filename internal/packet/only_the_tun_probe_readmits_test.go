package packet

import (
	"path/filepath"
	"testing"
)

func TestAProactiveRotationHandsADueEdgeLiveTraffic(t *testing.T) {
	p, now := clockPool([]string{"e1", "e2"}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
	if ip, _, _ := p.current(); ip != "e1" {
		t.Fatalf("setup: the cursor starts on %q, want e1", ip)
	}
	p.markSuspect("ip", "e2", "tun-probe")

	if p.advance() {
		t.Fatal("e2 is still waiting out its backoff, so there is nowhere to go — reporting a move tears " +
			"the live connection down every rotation tick for nothing")
	}
	if ip, _, _ := p.current(); ip != "e1" {
		t.Fatalf("the walk moved onto a waiting edge: %q", ip)
	}

	*now += suspectBackoff[0]
	if !p.advance() {
		t.Fatal("e2 came due and the rotation still would not go there — a burned edge that is never " +
			"selected can never be proven to have recovered, so it stays condemned forever")
	}
	ip, _, _ := p.current()
	if ip != "e2" {
		t.Fatalf("the rotation stepped onto e2 and current() resolved back to %q — the walk must not "+
			"re-select past the combination it deliberately moved onto", ip)
	}

	if ip2, _, _ := p.current(); ip2 != "e2" {
		t.Fatalf("the second ask gave %q — the commitment did not hold for the life of the attempt", ip2)
	}
}

func TestOnlyTheTunProbeEndsTheTry(t *testing.T) {
	t.Run("fail: burned again, and further down the ladder", func(t *testing.T) {
		p, now := clockPool([]string{"e1", "e2"}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
		p.markSuspect("ip", "e2", "tun-probe")
		*now += suspectBackoff[0]
		p.advance()
		ip, sni, _ := p.current()
		if ip != "e2" {
			t.Fatalf("setup: the try landed on %q", ip)
		}
		p.setActive(activeLabel(ip, sni.host))

		b := &TCP{pool: p}
		if !b.burnAdvanceWS(ip, sni.host) {
			t.Fatal("the verdict did nothing")
		}
		if p.ipHealth.due("e2") {
			t.Fatal("e2 is STILL due after failing the try the ladder granted it — every rotation tick " +
				"now returns to a proven-dead edge, drops the tunnel, and walks off it again, forever")
		}
		if got, _, _ := p.current(); got != "e1" {
			t.Fatalf("after the verdict the walk stayed on %q", got)
		}
	})

	t.Run("ok: cleared outright, no ladder left to wait out", func(t *testing.T) {
		p, now := clockPool([]string{"e1", "e2"}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
		p.markSuspect("ip", "e2", "tun-probe")
		*now += suspectBackoff[0]
		p.advance()

		if !p.clearBurn("ip", "e2") {
			t.Fatal("the tun probe said data crossed and the pool had nothing to clear")
		}
		if !p.ipHealth.healthy("e2") {
			t.Fatal("data crossed on e2 and it is not healthy — that IS the proof, and there is nothing " +
				"stronger the pool could ever be given")
		}
	})
}

func TestTheLadderDeepensOnTheRetryItsBackoffAllowed(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.now = func() int64 { return clk }
	p.fail()
	p.fail()

	addr := activeOf(p)
	p.mu.Lock()
	before := *p.health.rec(addr)
	p.mu.Unlock()

	p.fail()
	p.mu.Lock()
	held := *p.health.rec(addr)
	p.mu.Unlock()
	if held.fails != before.fails || held.nextRetest != before.nextRetest {
		t.Fatalf("%s is condemned and its backoff has not run out, yet a verdict deepened it anyway "+
			"(%+v -> %+v). At one verdict every three seconds that reaches the six-hour step in under a "+
			"minute, and every number the operator set on the way there means nothing", addr, before, held)
	}

	clk = before.nextRetest
	p.fail()
	p.mu.Lock()
	after := *p.health.rec(addr)
	p.mu.Unlock()
	if after.fails == before.fails && after.nextRetest == before.nextRetest {
		t.Fatalf("%s came due, was handed back, was tried, and failed, and its ladder did not move "+
			"(%+v) — the carrier would retry it at the shortest interval the ladder has, forever", addr, after)
	}
}

func TestAPinIsNotAProactiveRotation(t *testing.T) {
	p := newWSPool([]string{"e1", "e2", "e3"}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
	if !p.selectEntry("ip", "e3") {
		t.Fatal("could not pin e3")
	}
	for i := 0; i < 3; i++ {
		if p.advance() {
			t.Fatal("the rotation timer moved off a pinned edge — the operator's jump must survive it")
		}
		if ip, _, _ := p.current(); ip != "e3" {
			t.Fatalf("the pin resolved to %q", ip)
		}
	}
}
