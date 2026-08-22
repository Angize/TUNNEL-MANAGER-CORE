package packet

import "testing"

func TestAMultiEdgePoolBurnsTheEdgeFirst(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("only.example"))
	ip, sni, _ := p.current()
	b.pretendConnected(ip, sni.host)

	if !b.tunFail(t, ip, sni.host) {
		t.Fatal("the verdict did nothing")
	}

	p.mu.Lock()
	edgeBurned := !p.ipHealth.healthy(ip)
	sniBurned := !p.sniHealth.healthy(sni.host)
	p.mu.Unlock()

	if !edgeBurned {
		t.Fatalf("the dead edge %s was not blacklisted — the edge is the digit the walk varies, and it "+
			"is the cheap one: it comes back in ten minutes and it is what the filter actually blocks. "+
			"Nothing is set aside and the pool just cycles back onto it.", ip)
	}
	if sniBurned {
		t.Fatalf("the domain %s was burned on the FIRST beat — a domain is only condemned once every "+
			"edge under it has failed, because losing it loses it on every edge at once", sni.host)
	}
	if got, _, _ := p.current(); got == ip {
		t.Fatalf("still on %s after its verdict — the walk must move off it", ip)
	}
}

func TestASingleEdgePoolBurnsTheDomain(t *testing.T) {
	b, p := edgeCarrier(t, []string{"only.edge"}, snis("s1", "s2", "s3"))
	ip, sni, _ := p.current()
	b.pretendConnected(ip, sni.host)

	if !b.tunFail(t, ip, sni.host) {
		t.Fatal("the verdict did nothing")
	}
	p.mu.Lock()
	edgeBurned := !p.ipHealth.healthy(ip)
	sniBurned := !p.sniHealth.healthy(sni.host)
	p.mu.Unlock()

	if !sniBurned {
		t.Fatal("with ONE edge there is no cheaper digit to vary, so the walk arrives at the domain " +
			"every round and the domain is what a verdict names")
	}
	if edgeBurned {
		t.Fatalf("the only edge %s was burned — it never varied, so nothing distinguished it, and "+
			"burning it strands the only edge the pool has", ip)
	}
}

func TestASingleDestinationDirectPoolBurnsNothing(t *testing.T) {
	b, _, sp := peerCarrier(t, []string{"d1"}, []string{"s1", "s2"})
	src := sp.current()
	tcpWalk(b)

	b.pp.mu.Lock()
	burned := !b.pp.health.healthy("d1")
	b.pp.mu.Unlock()
	if burned {
		t.Fatal("the only destination was burned though nothing varied — and with one entry there is " +
			"nowhere for the pool to go, so the burn is pure loss")
	}
	if b.sp.current() == src {
		t.Fatal("the source did not move: with one destination it is the only axis left to walk")
	}
}
