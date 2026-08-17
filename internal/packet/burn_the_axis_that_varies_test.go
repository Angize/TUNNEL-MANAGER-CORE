package packet

import (
	"path/filepath"
	"testing"
)

// The probe sees SILENCE, and silence names the COMBINATION. The only thing that can be told apart is
// the axis the walk is CHANGING between combinations — so that is the axis a verdict may blame.
//
// This was read as "always burn the SNI", which is right only while there is more than one of them.

// TestASingleSNIPoolBurnsTheEdge is the case the operator hit, on a live tunnel with one domain and
// three CDN edges, one of them dead.
//
// With one SNI, burning the SNI was worse than useless: the lap is one beat long, so
// advanceEdgeFreshRow cleared the row on the very next line and the burn was undone as fast as it was
// made. NO edge was ever blacklisted. A pool sold as «چرخش + بلک‌لیست» only rotated — the dead edge came
// back every cycle, dropped the tunnel for a few seconds, and was walked off again, forever.
func TestASingleSNIPoolBurnsTheEdge(t *testing.T) {
	p := newWSPool([]string{"e1", "e2", "e3"}, snis("only.example"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{pool: p}
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))

	if !b.burnAdvanceWS(ip, sni.host) {
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

// TestAMultiSNIPoolStillBurnsTheSNI is the other half: with a real SNI axis the walk varies the SNI, so
// that is what a verdict names, and the edge is convicted only by a whole ROW failing on it. Losing this
// would make one bad domain condemn a perfectly good edge on its first beat.
func TestAMultiSNIPoolStillBurnsTheSNI(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2", "s3"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{pool: p}
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))

	if !b.burnAdvanceWS(ip, sni.host) {
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

// TestASingleDestinationDirectPoolBurnsNothing is the same question asked of the direct pool, and there
// the answer is already right: failWith refuses to burn when there is nothing to rotate to. A lone
// destination never varies either, and unlike a CDN edge the axis above it is a LOCAL source, which a tun
// probe is not allowed to blame at all — so the correct move is to burn nothing and walk the source.
func TestASingleDestinationDirectPoolBurnsNothing(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1"}, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")),
	}
	src := b.sp.current()
	b.burnAdvance(true)

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
