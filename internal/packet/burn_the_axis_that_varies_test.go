package packet

import "testing"

func TestASingleSNIPoolBurnsTheEdge(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("only.example"))
	ip, sni, _ := p.current()
	b.pretendConnected(sni.host, ip)

	if !b.tunFail(t, sni.host, ip) {
		t.Fatal("the verdict did nothing")
	}

	p.mu.Lock()
	edgeBurned := !p.ipHealth.healthy(ip)
	sniBurned := !p.sniHealth.healthy(sni.host)
	p.mu.Unlock()

	if !edgeBurned {
		t.Fatalf("the dead edge %s was not blacklisted — with one SNI the EDGE is the only thing the "+
			"walk varies, so it is the only thing a verdict can blame. Nothing is ever set aside and the "+
			"pool just cycles back onto it.", ip)
	}
	if sniBurned {
		t.Fatalf("the lone SNI %s was burned — it never varied, so nothing measured it, and with one "+
			"domain burning it also strands the only SNI the pool has", sni.host)
	}
	if got, _, _ := p.current(); got == ip {
		t.Fatalf("still on %s after its verdict — the walk must move off it", ip)
	}
}

func TestAMultiSNIPoolStillBurnsTheSNI(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("s1", "s2", "s3"))
	ip, sni, _ := p.current()
	b.pretendConnected(sni.host, ip)

	if !b.tunFail(t, sni.host, ip) {
		t.Fatal("the verdict did nothing")
	}
	p.mu.Lock()
	edgeBurned := !p.ipHealth.healthy(ip)
	sniBurned := !p.sniHealth.healthy(sni.host)
	p.mu.Unlock()

	if !sniBurned {
		t.Fatalf("with %d SNIs the walk varies the SNI, so the SNI is what a verdict names", 3)
	}
	if edgeBurned {
		t.Fatal("the edge was convicted on its FIRST beat — it is only guilty once a whole row of SNIs " +
			"has failed on it, which is the only thing that makes it the axis that did not vary")
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
