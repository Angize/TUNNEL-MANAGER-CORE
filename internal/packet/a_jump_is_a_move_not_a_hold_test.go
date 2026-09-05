package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// The pool is the only thing that knows where the tunnel is aimed, and the carrier is the only thing
// that can send there. Everything the "pin" used to do existed because those two could disagree: the
// cursor moved, the carrier kept its own copy, and a state machine ran between them to reconcile the
// two. The pool now publishes the ready-to-use address at the instant the cursor moves, under the same
// lock, and the carrier reads that -- so the disagreement it was reconciling cannot happen.
func TestThePublishedAddressFollowsEveryCursorMove(t *testing.T) {
	p := NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9", "10.0.0.3:9"}, 0)

	if a := p.liveAddr(); a == nil || a.s != "10.0.0.1:9" {
		t.Fatalf("a fresh pool publishes nothing: %+v", a)
	}

	for _, s := range []struct {
		name string
		run  func()
	}{
		{"a verdict", func() { p.fail("tun-probe") }},
		{"a rotation", func() { p.rotateOnce() }},
		{"a manual jump", func() { p.selectEntry("10.0.0.3:9") }},
		{"a plain read that has to settle", func() { p.current() }},
		{"the cursor being pulled back", func() { p.keepCursorOn("10.0.0.2:9") }},
		{"a candidate refused", func() { p.rejectCandidate("10.0.0.1:9") }},
		{"a burn forgiven", func() { p.clearBurn("10.0.0.1:9"); p.current() }},
	} {
		s.run()
		got, want := p.liveAddr(), p.current()
		if got == nil || got.s != want {
			t.Fatalf("after %s the carrier would send to %+v while the pool reports %q — that gap is "+
				"the whole reason a pin had to exist", s.name, got, want)
		}
	}
}

// The form is built once, when the pool is built. Reading it costs an atomic load, which is what the
// carriers already paid for their own copy; parsing it per packet would have cost 174ns and two
// allocations on the hot path.
func TestThePoolPublishesAReadyAddressNotAString(t *testing.T) {
	p := NewPeerPool([]string{"10.0.0.7:4500", "10.0.0.8:4500"}, 0)

	a := p.liveAddr()
	if a == nil {
		t.Fatal("nothing was published")
	}
	if a.ip == nil || !a.ip.IP.Equal(net.ParseIP("10.0.0.7")) {
		t.Fatalf("the raw carrier's form is %v, want 10.0.0.7", a.ip)
	}
	if a.ua == nil || a.ua.Port != 4500 || !a.ua.IP.Equal(net.ParseIP("10.0.0.7")) {
		t.Fatalf("the udp carrier's form is %v, want 10.0.0.7:4500", a.ua)
	}

	s := NewPeerPool([]string{"10.0.0.9"}, 0).liveAddr()
	if s == nil || s.ip == nil || !s.ip.IP.Equal(net.ParseIP("10.0.0.9")) {
		t.Fatalf("a source pool entry carries no address form: %+v", s)
	}
	if s.ua != nil {
		t.Fatalf("a bare source IP was given a udp form with port %d", s.ua.Port)
	}
}

// The two carriers that send from a hot path have to be aimed by the pool itself, with nothing to
// register and nothing to remember to call: a carrier holding the pool is aimed by it.
func TestTheDatagramCarriersReadTheJumpTheMomentItLands(t *testing.T) {
	t.Run("raw", func(t *testing.T) {
		pp := NewPeerPool([]string{"203.0.113.1", "203.0.113.2"}, 0)
		r := &Raw{isClient: true, pp: pp}
		if got := r.dst(); got == nil || got.IP.String() != "203.0.113.1" {
			t.Fatalf("holding the pool did not aim the carrier: %v", got)
		}
		if !pp.selectEntry("203.0.113.2") {
			t.Fatal("selectEntry did not find the second entry")
		}
		if got := r.dst(); got == nil || got.IP.String() != "203.0.113.2" {
			t.Fatalf("the pool moved to 203.0.113.2 but the packets still go to %v", got)
		}
	})

	t.Run("udp", func(t *testing.T) {
		pp := NewPeerPool([]string{"203.0.113.1:500", "203.0.113.2:500"}, 0)
		b := &UDP{isClient: true, pp: pp}
		if got := b.dst(); got == nil || got.String() != "203.0.113.1:500" {
			t.Fatalf("holding the pool did not aim the carrier: %v", got)
		}
		if !pp.selectEntry("203.0.113.2:500") {
			t.Fatal("selectEntry did not find the second entry")
		}
		if got := b.dst(); got == nil || got.String() != "203.0.113.2:500" {
			t.Fatalf("the pool moved to 203.0.113.2:500 but the packets still go to %v", got)
		}
	})

	t.Run("no pool: the carrier keeps its own peer", func(t *testing.T) {
		r := &Raw{isClient: false}
		r.soloPeer.Store(&net.IPAddr{IP: net.ParseIP("198.51.100.4")})
		if got := r.dst(); got == nil || got.IP.String() != "198.51.100.4" {
			t.Fatalf("a server with no pool lost its learned peer: %v", got)
		}
		b := &UDP{}
		b.soloPeer.Store(&net.UDPAddr{IP: net.ParseIP("198.51.100.4"), Port: 7})
		if got := b.dst(); got == nil || got.String() != "198.51.100.4:7" {
			t.Fatalf("a server with no pool lost its learned peer: %v", got)
		}
	})
}

func jumpController(t *testing.T, rotate time.Duration) (*rotationController, *PeerPool) {
	t.Helper()
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, rotate)
	rc := newRotationController(dst, nil)
	rc.attachStatus(newCoreStatus(filepath.Join(t.TempDir(), "core.json"), ""))
	return rc, dst
}

// A jump is the operator saying "try this one". Handing it the ladder the previous address had already
// spent means the very first hiccup condemns it, so the try never happens.
func TestAJumpGivesTheNewAddressAWholeLadder(t *testing.T) {
	rc, dst := jumpController(t, 0)
	rolls, walks := 0, 0
	rc.port.setRoll(func() bool { rolls++; return true })
	rot := func(bool) { walks++ }

	for i := 0; i < portTries; i++ {
		rc.fail(rot, rot)
	}
	if rolls != portTries || walks != 0 {
		t.Fatalf("setup: rolls=%d walks=%d, want %d and 0", rolls, walks, portTries)
	}
	rc.fail(rot, rot)
	if rolls != portTries || walks != 1 {
		t.Fatalf("setup: the spent ladder must walk, got rolls=%d walks=%d", rolls, walks)
	}

	writeFileAtomic(rc.selbox, []byte(`{"kind":"dst","key":"d3"}`), 0o644)
	if !rc.poll(rot, rot, nil, func() int64 { return 0 }) {
		t.Fatal("the jump was not applied")
	}
	if got := dst.current(); got != "d3" {
		t.Fatalf("the pool is on %q after a jump to d3", got)
	}

	rc.fail(rot, rot)
	if rolls != portTries+1 {
		t.Fatalf("the first hiccup on the operator's own pick went straight to a walk (rolls=%d): the "+
			"jump inherited the previous address's spent ladder", rolls)
	}
}

// Same reasoning for the clock: land on B with two seconds left of the rotation period and B is gone
// before the operator has finished reading the panel.
func TestAJumpRestartsTheRotationClock(t *testing.T) {
	const period = 40 * time.Second
	rc, dst := jumpController(t, period)

	rc.mu.Lock()
	rc.rotateAt = time.Now().Add(time.Second)
	rc.mu.Unlock()

	writeFileAtomic(rc.selbox, []byte(`{"kind":"dst","key":"d3"}`), 0o644)
	if !rc.poll(func(bool) {}, func(bool) {}, nil, func() int64 { return 0 }) {
		t.Fatal("the jump was not applied")
	}
	if got := dst.current(); got != "d3" {
		t.Fatalf("the pool is on %q after a jump to d3", got)
	}

	rc.mu.Lock()
	left := time.Until(rc.rotateAt)
	rc.mu.Unlock()
	if left < period-5*time.Second {
		t.Fatalf("only %v of the %v period is left after the jump — the operator's pick is rotated "+
			"away almost immediately", left.Round(time.Second), period)
	}
}

// The one rule the operator asked for in so many words: the rotation does not stop, ever, and it
// carries on FROM where they put it.
func TestRotationNeverStopsAfterAJumpAndResumesFromIt(t *testing.T) {
	rc, dst := jumpController(t, time.Millisecond)
	if !dst.selectEntry("d3") {
		t.Fatal("selectEntry did not find d3")
	}
	moves := 0
	rot := func(bool) { moves++; dst.rotateOnce() }

	rc.proactive(rot, func(bool) {}, time.Now().Add(time.Second))
	if moves == 0 {
		t.Fatal("the rotation timer refused to fire after a manual jump")
	}
	if got := dst.current(); got != "d1" {
		t.Fatalf("rotation resumed at %q; from d3 the next entry is d1", got)
	}
}

// The same rule on the edge pool, which is where the timer used to be told to stand down.
func TestTheEdgeRotationNeverStopsAfterAJump(t *testing.T) {
	p := newWSPool([]string{"e1", "e2", "e3"}, snis("x"))
	if !p.selectEntry("ip", "e3") {
		t.Fatal("could not jump to e3")
	}
	if ip, _, _ := p.current(); ip != "e3" {
		t.Fatalf("the jump did not land: %q", ip)
	}
	if !p.advance() {
		t.Fatal("the rotation timer refused to move after a manual jump — the operator asked for a " +
			"jump, not a hold")
	}
	if ip, _, _ := p.current(); ip != "e1" {
		t.Fatalf("rotation resumed at %q; from e3 the next edge is e1", ip)
	}
}
