package packet

import "testing"

func TestLoopWholeEdgeOutage(t *testing.T) {
	b, pp, sp := edgeCarrier(t, []string{"e1", "e2"}, snis("s1", "s2"))
	clk := int64(10000)
	pp.now = func() int64 { return clk }
	sp.now = func() int64 { return clk }
	armAndSpendTheFreeRungs(t, b)

	seen := map[string]int{}
	edges := map[string]bool{}
	for round := 1; round <= 4; round++ {
		ip, e, _ := b.edgeCombo()
		b.pretendConnected(ip, e.host)
		seen[ip+"|"+e.host]++
		edges[ip] = true
		if !b.tunFailUntilItMoves(t, ip, e.host) {
			t.Fatalf("round %d: the pool would not move off %s/%s", round, ip, e.host)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("four rounds only reached %d combinations: %v — the walk is not covering the matrix", len(seen), seen)
	}
	if len(edges) < 2 {
		t.Fatalf("four rounds never left edge %v — the edge axis never turned", edges)
	}

	ip, e, _ := b.edgeCombo()
	b.pretendConnected(ip, e.host)
	pp.markSuspect(ip, "test")
	sp.markSuspect(e.host, "test")
	b.tunOK(t, ip, e.host)
	pp.mu.Lock()
	stillIP := !pp.health.healthy(ip)
	pp.mu.Unlock()
	sp.mu.Lock()
	stillSNI := !sp.health.healthy(e.host)
	sp.mu.Unlock()
	if stillIP || stillSNI {
		t.Fatalf("a carrying combination stayed condemned: ip=%v sni=%v", stillIP, stillSNI)
	}

	b.operatorJump(t, "ip", "e2")
	if got := pp.current(); got != "e2" {
		t.Fatalf("the operator's jump did not land after a run of verdicts: current=%s", got)
	}
}

func TestLoopWholeDirectOutage(t *testing.T) {
	b, pp, sp := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})
	dsts, srcs := map[string]bool{}, map[string]bool{}
	for round := 1; round <= 6; round++ {
		dsts[pp.current()] = true
		srcs[sp.current()] = true
		tcpWalk(b)
	}
	if len(dsts) < 3 {
		t.Fatalf("six rounds reached %d of 3 destinations: %v", len(dsts), dsts)
	}
	if len(srcs) < 2 {
		t.Fatalf("six rounds never moved the source: %v — the odometer's high digit is stuck", srcs)
	}
}
