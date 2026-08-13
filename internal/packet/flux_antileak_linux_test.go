package packet

import (
	"net"
	"strings"
	"testing"
	"time"
)

// TestFluxRotationPreScopesAntiLeak drives the REAL rotation and pin entry points and asserts the
// anti-leak rule is re-scoped there — on the rotation timer's own goroutine — instead of being deferred
// into the receive loop. It also pins the install-before-remove order. A rule still scoped to the
// endpoint we left lets our kernel answer the new one's first frames with the leak it exists to prevent.
func TestFluxRotationPreScopesAntiLeak(t *testing.T) {
	defer func(d time.Duration) { antiLeakLinger = d }(antiLeakLinger)
	antiLeakLinger = 20 * time.Millisecond // the displaced rule goes on its own timer; see the linger test
	rec := &leakRecorder{}
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false, 0, "")
	f := &Flux{carrier: "udp", pp: pool, closeCh: make(chan struct{})}
	f.leak.init(f.closeCh, rec.install)
	f.localIP.Store(&net.IPAddr{IP: net.ParseIP("10.9.9.9")}) // learnLocalIP must not resolve a route

	first := hostOnly(pool.current())
	f.rotatePeerFlux(true)
	second := hostOnly(pool.current())
	if second == first {
		t.Fatalf("the pool did not rotate (still %s) — the test proves nothing", first)
	}
	if ev := rec.events(); len(ev) != 1 || ev[0] != "add "+second {
		t.Fatalf("rotation did not pre-scope the anti-leak rule to %s: %v", second, ev)
	}

	// The first authenticated frame from the new destination now costs NOTHING: the desired scope is
	// already the installed one, so the receive path takes the fast path and forks no process at all.
	f.learnPeer(&net.IPAddr{IP: net.ParseIP(second)})
	time.Sleep(100 * time.Millisecond) // an async re-scope would have landed well inside this
	if ev := rec.events(); len(ev) != 1 {
		t.Fatalf("the receive path re-scoped a rule the rotation had already installed: %v", ev)
	}

	// A second rotation must INSTALL the new scope BEFORE removing the old one. Removing first left a
	// window with no rule at all, and the endpoint we just left is deliberately still admitted for the
	// frames in flight from it — so that gap is when the kernel leaks.
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

	// An operator pin re-scopes on the pin poller's goroutine too, not in the data path.
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

// TestFluxLearnPeerNeverBlocksOnIptables is the one that matters for throughput: a re-scope the rotation
// could NOT predict — a server following the client's SOURCE rotation, or a pool server still answering
// from its previous IP — is discovered by the first authenticated frame, on the single AF_PACKET receive
// goroutine. That goroutine IS the data path, and each re-scope forks a process per rule, twice over.
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
	<-installing // the re-scope really did start, just not on the caller's goroutine
	waitFor(t, 5*time.Second, "the anti-leak rule was re-scoped off the receive path", func() bool {
		ev := rec.events()
		return len(ev) == 1 && strings.HasPrefix(ev[0], "add 10.0.0.42")
	})
}
