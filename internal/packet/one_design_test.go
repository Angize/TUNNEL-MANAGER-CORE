package packet

import "testing"

func TestLoopWholeEdgeOutage(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("s1", "s2"))
	clk := int64(10000)
	p.now = func() int64 { return clk }
	armAndSpendTheFreeRungs(t, b)

	seen := map[string]int{}
	edges := map[string]bool{}
	for round := 1; round <= 4; round++ {
		ip, e, _ := p.current()
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
		t.Fatalf("four rounds never left edge %v — the high digit never turned", edges)
	}

	ip, e, _ := p.current()
	b.pretendConnected(ip, e.host)
	p.markSuspect("ip", ip, "test")
	p.markSuspect("sni", e.host, "test")
	b.tunOK(t, ip, e.host)
	p.mu.Lock()
	stillIP, stillSNI := !p.ipHealth.healthy(ip), !p.sniHealth.healthy(e.host)
	p.mu.Unlock()
	if stillIP || stillSNI {
		t.Fatalf("a carrying combination stayed condemned: ip=%v sni=%v", stillIP, stillSNI)
	}

	b.operatorPin(t, "ip", "e2")
	if got, _, _ := p.current(); got != "e2" {
		t.Fatalf("the operator's pin did not land after a run of verdicts: current=%s", got)
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
