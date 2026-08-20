package packet

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestFluxRotationPreScopesAntiLeak(t *testing.T) {
	defer func(d time.Duration) { antiLeakLinger = d }(antiLeakLinger)
	antiLeakLinger = 20 * time.Millisecond
	rec := &leakRecorder{}
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	f := &Flux{carrier: "udp", pp: pool, closeCh: make(chan struct{})}
	f.leak.init(f.closeCh, rec.install)
	f.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")})

	first := hostOnly(pool.current())
	f.rotatePeerFlux(true)
	second := hostOnly(pool.current())
	if second == first {
		t.Fatalf("the pool did not rotate (still %s) — the test proves nothing", first)
	}
	if ev := rec.events(); len(ev) != 1 || ev[0] != "add "+second {
		t.Fatalf("rotation did not pre-scope the anti-leak rule to %s: %v", second, ev)
	}

	f.learnPeer(&net.IPAddr{IP: net.ParseIP(second)})
	time.Sleep(100 * time.Millisecond)
	if ev := rec.events(); len(ev) != 1 {
		t.Fatalf("the receive path re-scoped a rule the rotation had already installed: %v", ev)
	}

	f.rotatePeerFlux(true)
	third := hostOnly(pool.current())
	waitFor(t, 5*time.Second, "the rule for the endpoint we left was removed after its linger", func() bool {
		return evIndex(rec.events(), "del "+second) >= 0
	})
	ev := rec.events()
	addNew, delOld := evIndex(ev, "add "+third), evIndex(ev, "del "+second)
	if addNew < 0 || delOld < 0 {
		t.Fatalf("second rotation did not re-scope (want add %s then del %s): %v", third, second, ev)
	}
	if addNew > delOld {
		t.Fatalf("the old scope was removed before the new one was installed — an ICMP leak window: %v", ev)
	}

	pinTarget := "10.0.0.1"
	if pinTarget == third {
		pinTarget = "10.0.0.2"
	}
	if !pool.selectEntry(pinTarget) {
		t.Fatalf("selectEntry(%s) refused the pin", pinTarget)
	}
	f.adoptPeerFlux()
	if ev := rec.events(); evIndex(ev, "add "+pinTarget) < 0 {
		t.Fatalf("a pin did not pre-scope the anti-leak rule to %s: %v", pinTarget, ev)
	}
}

func TestFluxLearnPeerNeverBlocksOnIptables(t *testing.T) {
	installing := make(chan struct{})
	rec := &leakRecorder{delay: 750 * time.Millisecond, tookTo: installing}
	f := &Flux{carrier: "stun", closeCh: make(chan struct{})}
	f.leak.init(f.closeCh, rec.install)
	f.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")})

	start := time.Now()
	f.learnPeer(&net.IPAddr{IP: net.ParseIP("10.0.0.42")})
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("learnPeer held the AF_PACKET receive goroutine for %v while iptables ran", el)
	}
	<-installing
	waitFor(t, 5*time.Second, "the anti-leak rule was re-scoped off the receive path", func() bool {
		ev := rec.events()
		return len(ev) == 1 && strings.HasPrefix(ev[0], "add 10.0.0.42")
	})
}
