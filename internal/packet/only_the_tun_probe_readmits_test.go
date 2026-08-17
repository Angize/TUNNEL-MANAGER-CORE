package packet

import (
	"path/filepath"
	"testing"
)

// An edge is readmitted by DATA CROSSING and by nothing else. That one sentence has two halves, and the
// pool used to have only the first: it knew how to condemn an edge, and then leaned on a control-path
// retest -- TCP, TLS, the WebSocket upgrade -- to declare it well again. All three can complete on an edge
// that carries nothing, which is precisely the failure this whole pool exists to survive.
//
// Taking that away leaves a hole that has to be filled deliberately, and it is the part that is easy to
// miss: the tun probe can only judge an edge that is CARRYING, and the walk only ever selected healthy
// combinations, so a burned edge would never carry again as long as one healthy edge remained. Condemned
// once, condemned for the life of the pool. The proactive rotation is what closes it -- it steps onto
// entries whose backoff has ELAPSED, exactly as the direct pool's rotation already did.

// TestAProactiveRotationHandsADueEdgeLiveTraffic is that hole, end to end on the pool: the wait is
// honoured, then the rotation spends a real connection on the burned edge, and current() must not walk
// back off it before the probe has had its say.
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

	*now += suspectBackoff[0] // its wait elapsed: the ladder itself says "try this again"
	if !p.advance() {
		t.Fatal("e2 came due and the rotation still would not go there — a burned edge that is never " +
			"selected can never be proven to have recovered, so it stays condemned forever")
	}
	ip, _, _ := p.current()
	if ip != "e2" {
		t.Fatalf("the rotation stepped onto e2 and current() resolved back to %q — the walk must not "+
			"re-select past the combination it deliberately moved onto", ip)
	}
	// ...and it keeps resolving there, because the carrier asks again on every dial.
	if ip2, _, _ := p.current(); ip2 != "e2" {
		t.Fatalf("the second ask gave %q — the commitment did not hold for the life of the attempt", ip2)
	}
}

// TestOnlyTheTunProbeEndsTheTry is the other side of that live try: whatever the pool learns from it, it
// learns from the node's verdict. A FAIL must also cost e2 a ladder step, or it stays due and the very
// next rotation tick walks straight back onto it: the dead edge coming back every cycle, which is what
// the operator watched happen on a live tunnel.
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
		if !b.burnAdvanceWS(ip, sni.host) { // one SNI: the EDGE is the axis that varied
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

// TestTheLadderStillDeepensWhenEverythingIsBurned is the case that "a verdict only counts against an
// entry the pool actually TRIED" could have frozen. With nothing healthy and nothing due, the pool still
// has to hand something back rather than dead-end the tunnel — and the carrier then spends a real
// connection on it. That try has to count, or every endpoint sits at its first backoff step forever and
// the carrier hammers the whole pool at the shortest interval the ladder has.
func TestTheLadderStillDeepensWhenEverythingIsBurned(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0, "")
	p.now = func() int64 { return clk }
	p.fail() // burns a, moves to b
	p.fail() // burns b — now nothing is healthy and nothing is due

	addr := p.current() // the least-bad, handed out anyway
	p.mu.Lock()
	before := *p.health.rec(addr)
	p.mu.Unlock()

	p.fail() // ...and the carrier failed on it
	p.mu.Lock()
	after := *p.health.rec(addr)
	p.mu.Unlock()
	if after.fails == before.fails && after.nextRetest == before.nextRetest {
		t.Fatalf("%s was handed out, tried, and failed, and its ladder did not move (%+v) — with every "+
			"endpoint burned the pool keeps handing one back, so a verdict that costs nothing leaves the "+
			"carrier retrying the same ones at the shortest interval the ladder has, forever", addr, after)
	}
}

// TestAPinIsNotAProactiveRotation guards the seam the commitment opened: advance() now moves the walk on
// its own, so it has to refuse while an operator pin is in force, or the timer silently steals the jump
// the operator asked for.
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
