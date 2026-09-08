package packet

import "testing"

// Three edges under one domain: the walk burns the edge it is standing on and steps to the next one.
// The domain is left alone -- the odometer has not lapped, and losing a domain loses it on every edge.
func TestAMultiEdgePoolBurnsTheEdgeFirst(t *testing.T) {
	b, pp, sp := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("only.example"))
	ip, sni, _ := b.edgeCombo()
	b.pretendConnected(ip, sni.host)

	if !b.tunFail(t, ip, sni.host) {
		t.Fatal("the verdict did nothing")
	}

	pp.mu.Lock()
	edgeBurned := !pp.health.healthy(ip)
	pp.mu.Unlock()
	sp.mu.Lock()
	sniBurned := !sp.health.healthy(sni.host)
	sp.mu.Unlock()

	if !edgeBurned {
		t.Fatalf("the dead edge %s was not blacklisted — the edge is the digit the walk varies, and it "+
			"is the cheap one: it comes back in ten minutes and it is what the filter actually blocks. "+
			"Nothing is set aside and the pool just cycles back onto it.", ip)
	}
	if sniBurned {
		t.Fatalf("the domain %s was burned on the FIRST beat — a domain is only condemned once every "+
			"edge under it has failed, because losing it loses it on every edge at once", sni.host)
	}
	if got := pp.current(); got == ip {
		t.Fatalf("still on %s after its verdict — the walk must move off it", ip)
	}
}

// One edge under three domains: the walk burns the lone edge all the same, and the odometer laps on the
// first beat, so the domain is condemned on that same beat. The domain step then restores the whole
// edge health set, so the edge burn is on the counter and the row is green again by the time it returns.
func TestASingleEdgePoolBurnsBothItsEdgeAndItsDomain(t *testing.T) {
	b, pp, sp := edgeCarrier(t, []string{"only.edge"}, snis("s1", "s2", "s3"))
	ip, sni, _ := b.edgeCombo()
	b.pretendConnected(ip, sni.host)

	if !b.tunFail(t, ip, sni.host) {
		t.Fatal("the verdict did nothing")
	}

	sp.mu.Lock()
	sniBurned := !sp.health.healthy(sni.host)
	sp.mu.Unlock()
	if !sniBurned {
		t.Fatal("with ONE edge there is no cheaper digit to vary, so the walk arrives at the domain " +
			"every round and the domain is what a verdict names")
	}
	if pp.burnCount() == 0 {
		t.Fatalf("the only edge %s was not condemned — the walk burns the entry it is standing on "+
			"before it goes looking, and having nowhere to go is not a defence", ip)
	}
	pp.mu.Lock()
	stillBurned := !pp.health.healthy(ip)
	pp.mu.Unlock()
	if stillBurned {
		t.Fatalf("%s was left condemned after the domain stepped — a domain step restores the edge "+
			"set, because every edge earns a fresh trial under a domain it has not been tried on", ip)
	}
}

// One destination, two sources: the walk burns the lone destination too, and the source step that
// follows restores it. The counter is the only honest record -- the row is green again on return.
func TestASingleDestinationIsBurnedThenRestoredByTheSourceStep(t *testing.T) {
	b, pp, sp := peerCarrier(t, []string{"d1"}, []string{"s1", "s2"})
	src := sp.current()
	tcpWalk(b)

	if pp.burnCount() == 0 {
		t.Fatal("the only destination was not condemned — PeerPool.fail burns the entry it is " +
			"standing on first and only then looks for a better one, and one entry buys no exemption")
	}
	pp.mu.Lock()
	burned := !pp.health.healthy("d1")
	pp.mu.Unlock()
	if burned {
		t.Fatal("the only destination was left condemned — the source step restores the destination " +
			"set, so nothing is stranded behind a burn it can never rotate away from")
	}
	if sp.current() == src {
		t.Fatal("the source did not move: with one destination it is the only axis left to walk")
	}
}
