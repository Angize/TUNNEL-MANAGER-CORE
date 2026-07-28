package packet

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fluxLeakRecorder stands in for addFluxDrop: it records every install and every removal, in order,
// and can be made slow so a caller that waits for iptables is visible as elapsed time. Nothing here
// reaches the host firewall.
type fluxLeakRecorder struct {
	mu     sync.Mutex
	ev     []string
	delay  time.Duration
	tookTo chan struct{}
}

func (r *fluxLeakRecorder) install(peer net.IP, carrier string) func() {
	r.mu.Lock()
	if r.tookTo != nil {
		close(r.tookTo)
		r.tookTo = nil
	}
	r.mu.Unlock()
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	ip := peer.String()
	r.mu.Lock()
	r.ev = append(r.ev, "add "+ip)
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.ev = append(r.ev, "del "+ip)
		r.mu.Unlock()
	}
}

func (r *fluxLeakRecorder) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ev...)
}

func evIndex(ev []string, want string) int {
	for i, e := range ev {
		if e == want {
			return i
		}
	}
	return -1
}

// TestFluxRotationPreScopesAntiLeak drives the REAL rotation and pin entry points and asserts that
// the anti-leak rule is re-scoped there — on the rotation timer's own goroutine — instead of being
// deferred into the receive loop. It also pins the install-before-remove order.
//
// Before the fix rotatePeerFlux/adoptPeerFlux stored the new peer and nothing else, so the rule stayed
// scoped to the endpoint we had just left. Our kernel then answered the new endpoint's first frames
// with ICMP unreachables — the exact leak the rule exists to prevent — until one of them reached
// learnPeer, which fixed it by forking 10 to 16 iptables processes on the AF_PACKET receive goroutine.
func TestFluxRotationPreScopesAntiLeak(t *testing.T) {
	rec := &fluxLeakRecorder{}
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, false, 0, "")
	f := &Flux{carrier: "udp", pp: pool, closeCh: make(chan struct{}), dropInstall: rec.install}
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

// TestFluxLearnPeerNeverBlocksOnIptables is the one that matters for throughput: a re-scope the
// rotation could NOT predict — a server following the client's SOURCE rotation, or a pool server still
// answering from its previous IP — is discovered by the first authenticated frame, which arrives on
// the single AF_PACKET receive goroutine. That goroutine IS the data path, and each re-scope runs a
// process per rule (8 for the raw carrier, 5 for udp/stun) twice over. Before the fix it ran inline.
func TestFluxLearnPeerNeverBlocksOnIptables(t *testing.T) {
	installing := make(chan struct{})
	rec := &fluxLeakRecorder{delay: 750 * time.Millisecond, tookTo: installing}
	f := &Flux{carrier: "raw", closeCh: make(chan struct{}), dropInstall: rec.install}
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
