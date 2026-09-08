package packet

import "testing"

// core13's real shape on 2026-08-21: three edges, ONE domain. The walk varies the edge and turns the
// domain once the row is spent. Turning it here means turning it onto itself -- but the burn is still
// recorded, because a green domain under a dead tunnel is the one thing the operator must not be told.
func TestALoneDomainIsStillCondemned(t *testing.T) {
	b, pp, sp := edgeCarrier(t, []string{"ip1", "ip2", "ip3"}, snis("cdn.example"))
	b.rc.port.setRoll(func() bool { return true })

	for round := 1; round <= 6*(portTries+1); round++ {
		ip, sni, _ := b.edgeCombo()
		b.noteAttempt(ip, sni.host)
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	sp.mu.Lock()
	domainGreen := sp.health.healthy("cdn.example")
	sp.mu.Unlock()
	if domainGreen {
		t.Error("the only domain stayed green after every edge under it had failed — nothing rotates " +
			"away from it, but the panel then shows a healthy domain on a tunnel carrying nothing")
	}

	pp.mu.Lock()
	burned := 0
	for _, k := range pp.addrs {
		if !pp.health.healthy(k) {
			burned++
		}
	}
	pp.mu.Unlock()
	if burned == 0 {
		t.Error("and the edges — the axis that actually varied — were left green")
	}
}

// The mirror: one edge, several domains. The edge is the axis with nowhere to go, and it is condemned
// all the same -- PeerPool.fail burns the entry it is standing on before it looks for a better one, so
// an axis of one buys no exemption. The domain step that follows restores the whole edge health set,
// which is why the burn shows on the counter and not on the row.
func TestALoneEdgeIsCondemnedToo(t *testing.T) {
	b, pp, sp := edgeCarrier(t, []string{"only.edge"}, snis("s1", "s2", "s3"))
	b.rc.port.setRoll(func() bool { return true })

	for round := 1; round <= 2*(portTries+1); round++ {
		ip, sni, _ := b.edgeCombo()
		b.noteAttempt(ip, sni.host)
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	if pp.burnCount() == 0 {
		t.Error("the only edge was never condemned — the walk burns what it is standing on before it " +
			"looks for somewhere better, and having nowhere to go is not a defence")
	}
	sp.mu.Lock()
	domainGreen := sp.health.healthy("s1")
	sp.mu.Unlock()
	if domainGreen {
		t.Error("and the domain was not condemned either; with one edge the domain is the digit the " +
			"walk varies, so it is what a verdict names")
	}
}
