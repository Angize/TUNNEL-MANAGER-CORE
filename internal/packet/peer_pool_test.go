package packet

import (
	"net"
	"testing"
)

func TestPeerPoolRotateCycles(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	if p.current() != "a" {
		t.Fatalf("first current = %q, want a", p.current())
	}
	got := []string{}
	for i := 0; i < 4; i++ {
		a, moved := p.rotateOnce()
		if !moved {
			t.Fatal("rotateOnce should move in a 3-endpoint pool")
		}
		got = append(got, a)
	}
	// a -> b, c, a, b (proactive, no burns)
	want := []string{"b", "c", "a", "b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotation order = %v, want %v", got, want)
		}
	}
}

func TestPeerPoolBurnSkipsAndAdvances(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	// active is a; a fails -> burned, advance to b
	if a, moved := p.fail(); a != "b" || !moved {
		t.Fatalf("after burning a, got %q moved=%v, want b true", a, moved)
	}
	// b fails -> burned, advance to c (a still burned, skipped)
	if a, _ := p.fail(); a != "c" {
		t.Fatalf("after burning b, got %q, want c", a)
	}
	// proactive rotate should now skip the two burned (a,b) and stay on c
	if a, moved := p.rotateOnce(); a != "c" || moved {
		t.Fatalf("only c is live: got %q moved=%v, want c false", a, moved)
	}
}

func TestPeerPoolRevivesWhenAllBurned(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.fail() // burn a -> advance to b
	// burning the last live endpoint must revive all AND still move (never dead-end, never re-stick)
	a, moved := p.fail() // burn b -> revive all, advance off b back to a
	// after revival nothing is burned; both are candidates again
	p.mu.Lock()
	nb := len(p.burned)
	p.mu.Unlock()
	if nb != 0 {
		t.Fatalf("all-burned should revive to 0 burned, got %d", nb)
	}
	if !moved || a != "a" {
		t.Fatalf("after all-burned revive: got %q moved=%v, want a true (advance off the failed endpoint)", a, moved)
	}
}

func TestPeerPoolAutoBurnOffJustRotates(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, false, 0, "") // auto-burn OFF
	p.fail()
	p.mu.Lock()
	nb := len(p.burned)
	p.mu.Unlock()
	if nb != 0 {
		t.Fatalf("auto-burn off must not burn, got %d burned", nb)
	}
}

func TestPeerPoolSucceededClearsBurn(t *testing.T) {
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	p.fail() // burn a, now on b
	// pretend we later rotate back onto a and it works
	p.mu.Lock()
	p.cur = 0 // force active = a (still burned)
	p.mu.Unlock()
	p.succeeded()
	p.mu.Lock()
	burnedA := p.burned["a"]
	p.mu.Unlock()
	if burnedA {
		t.Fatal("succeeded() must clear the active endpoint's burn")
	}
}

func TestPeerPoolSingleEndpointNoop(t *testing.T) {
	p := NewPeerPool([]string{"only"}, true, 0, "")
	if a, moved := p.fail(); a != "only" || moved {
		t.Fatalf("single-endpoint fail = %q moved=%v, want only false", a, moved)
	}
	if a, moved := p.rotateOnce(); a != "only" || moved {
		t.Fatalf("single-endpoint rotate = %q moved=%v, want only false", a, moved)
	}
}

// TestTCPDialTargetUsesPool verifies the TCP integration points without a real dial: dialTarget
// reads the pool's current endpoint when a pool is wired and falls back to the fixed peer otherwise,
// and a ws client refuses the pool (the ws edge pool owns rotation there).
func TestTCPDialTargetUsesPool(t *testing.T) {
	b := &TCP{isClient: true, addr: "1.1.1.1:9000"}
	if got := b.dialTarget(); got != "1.1.1.1:9000" {
		t.Fatalf("no pool: dialTarget = %q, want the fixed peer", got)
	}
	b.SetPeerPool(NewPeerPool([]string{"2.2.2.2:9000", "3.3.3.3:9000"}, true, 0, ""))
	if b.pp == nil {
		t.Fatal("direct-tcp client should accept a peer pool")
	}
	if got := b.dialTarget(); got != "2.2.2.2:9000" {
		t.Fatalf("with pool: dialTarget = %q, want the pool's current endpoint", got)
	}
	// After burning the current endpoint the next dial must target the advanced one.
	b.pp.fail()
	if got := b.dialTarget(); got != "3.3.3.3:9000" {
		t.Fatalf("after burn: dialTarget = %q, want the next endpoint", got)
	}

	// A ws client must NOT accept a peer pool — ws has its own edge pool.
	w := &TCP{isClient: true, ws: true, addr: "1.1.1.1:443"}
	w.SetPeerPool(NewPeerPool([]string{"2.2.2.2:443", "3.3.3.3:443"}, true, 0, ""))
	if w.pp != nil {
		t.Fatal("ws client must reject a peer pool")
	}
	if got := w.dialTarget(); got != "1.1.1.1:443" {
		t.Fatalf("ws client: dialTarget = %q, want the fixed addr", got)
	}
}

func TestTCPSourceIPUsesPool(t *testing.T) {
	b := &TCP{isClient: true, bindIP: "10.0.0.1"}
	if got := b.sourceIP(); got != "10.0.0.1" {
		t.Fatalf("no source pool: sourceIP = %q, want the fixed bindIP", got)
	}
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, true, 0, ""))
	if b.sp == nil {
		t.Fatal("direct-tcp client should accept a source pool")
	}
	if got := b.sourceIP(); got != "10.0.0.5" {
		t.Fatalf("with source pool: sourceIP = %q, want the pool's current", got)
	}
	if !b.rotateSourceTCP(true) { // proactive rotate should move in a 2-entry pool
		t.Fatal("rotateSourceTCP should report moved=true")
	}
	if got := b.sourceIP(); got != "10.0.0.6" {
		t.Fatalf("after rotate: sourceIP = %q, want the advanced source", got)
	}
	// ws client must refuse a source pool (its edge pool owns rotation).
	w := &TCP{isClient: true, ws: true, bindIP: "10.0.0.1"}
	w.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, true, 0, ""))
	if w.sp != nil {
		t.Fatal("ws client must reject a source pool")
	}
}

// TestUDPSourceRebindSwapsConn checks the udp source-rotation mechanics: rotateSourceUDP opens a fresh
// socket on the new source IP, swaps it in, and bumps rebindGen so the receive loop knows the old
// socket's imminent read error is a deliberate swap (not a death). Uses loopback (127.0.0.0/8).
func TestUDPSourceRebindSwapsConn(t *testing.T) {
	c0, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("initial ListenUDP: %v", err)
	}
	b := &UDP{isClient: true}
	b.conn.Store(c0)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, true, 0, ""))
	gen0 := b.rebindGen.Load()

	b.rotateSourceUDP(true) // advance 127.0.0.1 -> 127.0.0.2 and rebind
	if b.rebindGen.Load() == gen0 {
		t.Fatal("rebindGen must advance on a source rebind so netToTun keeps the loop alive")
	}
	nc := b.conn.Load()
	if nc == c0 {
		t.Fatal("conn was not swapped")
	}
	if got := nc.LocalAddr().(*net.UDPAddr).IP; !got.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("rebound socket source = %v, want 127.0.0.2", got)
	}
	nc.Close() // c0 was already closed by rotateSourceUDP
}

// TestRotationControllerCouplesSource verifies the failover policy: burning destinations advances the
// source only once every destination has been tried against the current source.
func TestRotationControllerCouplesSource(t *testing.T) {
	dst := NewPeerPool([]string{"d0", "d1"}, true, 0, "") // size 2
	src := NewPeerPool([]string{"s0", "s1"}, true, 0, "")
	rc := newRotationController(dst, src)
	dstMoves, srcMoves := 0, 0
	rotDst := func(bool) { dstMoves++ }
	rotSrc := func(bool) { srcMoves++ }

	rc.fail(rotDst, rotSrc) // destRot 1
	if dstMoves != 1 || srcMoves != 0 {
		t.Fatalf("after 1 fail: dst=%d src=%d, want 1/0", dstMoves, srcMoves)
	}
	rc.fail(rotDst, rotSrc) // destRot 2 == size -> source advances, reset
	if dstMoves != 2 || srcMoves != 1 {
		t.Fatalf("after 2 fails: dst=%d src=%d, want 2/1 (source walked)", dstMoves, srcMoves)
	}
	rc.success() // clears the dest-cycle counter
	rc.fail(rotDst, rotSrc)
	if srcMoves != 1 {
		t.Fatalf("success() must reset destRot so the source doesn't advance early, got src=%d", srcMoves)
	}

	// Source-only pool (no destination pool) advances the source on every failure.
	rc2 := newRotationController(nil, NewPeerPool([]string{"s0", "s1"}, true, 0, ""))
	n := 0
	rc2.fail(func(bool) { t.Fatal("no dest pool: rotDst must not be called") }, func(bool) { n++ })
	if n != 1 {
		t.Fatalf("source-only fail should advance the source once, got %d", n)
	}
}
