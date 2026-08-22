//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
)

// A carrier that is up, so a rung has something to tear down. Closing it twice is harmless.
func liveCarrier(t *testing.T, b *TCP) net.Conn {
	t.Helper()
	c, other := net.Pipe()
	t.Cleanup(func() { c.Close(); other.Close() })
	b.curConn.Store(&c)
	return c
}

func rigTCP(t *testing.T, dsts []string) (*TCP, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "core.status")
	b := &TCP{isClient: true, stTag: "tcp", addr: "d1:443"}
	b.SetStatusPath(path)
	if len(dsts) > 0 {
		b.SetPeerPool(NewPeerPool(dsts, 0))
	}
	armLikeRun(b)
	b.st.tracker.observe(pathKey{Dst: "d1", Dport: 443, Src: "10.0.0.1", Sport: 40001}, true)
	liveCarrier(t, b)
	return b, path
}

func codes(evs []coreEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Code)
	}
	return out
}

func TestTheFreeRungIsSpentBeforeAnyDestinationBurns(t *testing.T) {
	b, path := rigTCP(t, []string{"d1", "d2"})
	epoch := b.st.pathEpoch()
	first := b.pp.current()

	for i := 1; i <= portTries; i++ {
		liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: first})
		b.pollPeerCmd()
		if burned := burnedIn(b.pp); len(burned) != 0 {
			t.Fatalf("draw %d of %d condemned %v. Every free rung must be spent before an endpoint is "+
				"blamed -- a socket carrier redials on a fresh ephemeral source port, which is the same "+
				"escape raw gets from rolling its crafted one", i, portTries, burned)
		}
		if !b.rolled.Load() {
			t.Fatalf("draw %d did not mark the disconnect as a rung redial; the dial loop would blame the "+
				"endpoint for a teardown the ladder asked for", i)
		}
		b.rolled.Store(false) // the dial loop consumes this; there is no dial loop here
		liveCarrier(t, b)
	}

	// The draws themselves are silent. What the operator gets is one line once the tunnel comes back,
	// naming the port it came back ON -- see TestAPortRedrawIsOnlyNewsIfItWorked. An outage that never
	// recovers writes nothing, which is the whole point: the ladder redraws every few seconds.
	if got := codes(coreStatusEvents(t, path)); len(got) != 0 {
		t.Fatalf("%d free draws published %v; a draw that has not been proven to work says nothing",
			portTries, got)
	}

	liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: first})
	b.pollPeerCmd()
	burned := burnedIn(b.pp)
	if len(burned) != 1 || !burned[first] {
		t.Fatalf("the verdict after the budget ran out burned %v, want exactly {%s} -- the ladder must "+
			"reach the burn, not loop on free rungs for ever", burned, first)
	}
}

func TestCarryingRefillsTheRungSoTheNextOutageGetsAWholeLadder(t *testing.T) {
	b, _ := rigTCP(t, []string{"d1", "d2"})
	epoch := b.st.pathEpoch()

	liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: b.pp.current()})
	b.pollPeerCmd()
	b.rolled.Store(false)
	liveCarrier(t, b)

	liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdOK, Low: b.pp.current()})
	b.pollPeerCmd()

	for i := 1; i <= portTries; i++ {
		liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: b.pp.current()})
		b.pollPeerCmd()
		if burned := burnedIn(b.pp); len(burned) != 0 {
			t.Fatalf("after a carrying sweep the budget was still %d/%d spent: draw %d already burned %v",
				portTries-i+1, portTries, i, burned)
		}
		b.rolled.Store(false)
		liveCarrier(t, b)
	}
}

func TestAPoolLessCarrierStillSpendsItsFreeRung(t *testing.T) {
	b, path := rigTCP(t, nil)
	if b.pp != nil || b.sp != nil || b.pool != nil {
		t.Fatal("setup: this rig must have no pool of any kind")
	}
	liveVerdict(t, b.st.verdictPath(), b.st.pathEpoch(), poolCmd{Cmd: cmdFail})

	b.pollPeerCmd()

	if !b.rolled.Load() {
		t.Fatal("a tunnel with no endpoint to burn got nothing at all from its verdict. The free rung " +
			"moves the tunnel nowhere and needs no second endpoint, so it is exactly what a pool-less " +
			"carrier can still spend")
	}
	if got := codes(coreStatusEvents(t, path)); len(got) != 0 {
		t.Fatalf("events = %v; the draw is spent but unproven, so it is not news yet", got)
	}
}

func TestWithNoCarrierTheRungIsSpentAndNothingIsTornDown(t *testing.T) {
	b, path := rigTCP(t, []string{"d1", "d2"})
	epoch := b.st.pathEpoch()
	first := b.pp.current()
	b.curConn.Store(nil)

	for i := 1; i <= portTries; i++ {
		liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: first})
		b.pollPeerCmd()
		if burned := burnedIn(b.pp); len(burned) != 0 {
			t.Fatalf("draw %d condemned %v while there was no carrier at all", i, burned)
		}
		if b.rolled.Load() {
			t.Fatal("the rung claimed it tore a carrier down when there was none to tear down; the dial " +
				"loop would then treat a real failure as a teardown the ladder asked for")
		}
	}

	liveVerdict(t, b.st.verdictPath(), epoch, poolCmd{Cmd: cmdFail, Low: first})
	b.pollPeerCmd()
	if burned := burnedIn(b.pp); !burned[first] {
		t.Fatalf("with no carrier the ladder never reached the burn (%v). A destination whose handshake "+
			"always fails leaves the dial loop between carriers for ever, and a direct pool has no other "+
			"way off it -- so the rungs must still run out", burned)
	}
	if got := codes(coreStatusEvents(t, path)); len(got) != 1 || got[0] != "tun-probe" {
		t.Fatalf("events = %v, want exactly the burn: the draws before it never proved themselves", got)
	}
}

func TestTheEdgePoolClimbsTheSameLadder(t *testing.T) {
	b, pool := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
	armLikeRun(b)
	liveCarrier(t, b)

	ip, sni, _ := pool.current()
	b.pretendConnected(ip, sni.host)
	b.st.tracker.observe(pathKey{Dst: ip, Dport: 443, Sport: 40001, SNI: sni.host}, true)
	epoch := b.st.pathEpoch()
	fail := poolCmd{Cmd: cmdFail, Low: ip, High: sni.host}

	burned := func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return !pool.ipHealth.healthy(ip)
	}

	for i := 1; i <= portTries; i++ {
		liveVerdict(t, b.st.verdictPath(), epoch, fail)
		b.pollPeerCmd()
		if burned() {
			t.Fatalf("draw %d of %d condemned edge %s. A free rung redials the SAME edge on a fresh "+
				"ephemeral source port and blames nobody; only the burn moves the pool", i, portTries, ip)
		}
		if !b.rolled.Load() {
			t.Fatalf("draw %d did not mark the disconnect as a rung redial; the dial loop would charge "+
				"the edge for a teardown the ladder asked for", i)
		}
		b.rolled.Store(false)
		liveCarrier(t, b)
	}

	liveVerdict(t, b.st.verdictPath(), epoch, fail)
	b.pollPeerCmd()
	if !burned() {
		t.Fatalf("the verdict after the %d-draw budget ran out left edge %s healthy: the edge pool never "+
			"reaches the burn", portTries, ip)
	}
}
