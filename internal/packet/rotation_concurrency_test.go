package packet

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPeerPoolUnderConcurrentDrivers(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	p := NewPeerPool([]string{"d1", "d2", "d3"}, 0)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}

	run(func() { p.current() })
	run(func() { p.fail("tun-probe") })
	run(func() { p.rotateOnce() })
	run(func() { p.selectEntry("d2") })
	run(func() { p.selectEntry("d1") })
	run(func() { p.clearBurn("d3") })
	run(func() { p.retestNow("d1") })
	run(func() { _ = p.eligibleCount() })
	run(func() { p.keepCursorOn(p.current()) })

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	got := p.current()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addrs[p.cur] != got {
		t.Fatalf("current() gave %q while the cursor names %q", got, p.addrs[p.cur])
	}
	if live := p.liveAddr(); live == nil || live.s != p.addrs[p.cur] {
		t.Fatalf("the carrier is reading %+v while the cursor names %q", live, p.addrs[p.cur])
	}
	if p.chosen != "" && p.addrs[p.cur] != p.chosen {
		t.Fatalf("chosen=%q while the cursor names %q", p.chosen, p.addrs[p.cur])
	}
	for k := range p.health.recs {
		found := false
		for _, a := range p.addrs {
			if a == k {
				found = true
			}
		}
		if !found {
			t.Fatalf("health map holds %q, which is not in the pool", k)
		}
	}
}

func TestEdgePoolUnderConcurrentDrivers(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	b, pp, sp := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("s1", "s2"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}

	run(func() { b.edgeCombo() })
	run(func() { b.walkEdge() })
	run(func() { pp.rotateOnce(); pp.restoreAll() })
	run(func() {
		if _, high := b.livePairNow(); high != "" {
			b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
		}
	})
	run(func() {
		if ip, sni, ok := b.edgeCombo(); ok {
			b.pretendConnected(ip, sni.host)
		}
	})
	run(func() { pp.selectEntry("e2") })
	run(func() { sp.selectEntry("s1") })
	run(func() { sp.clearBurn("s2") })
	run(func() { pp.clearBurn("e3") })
	run(func() { _ = pp.eligibleCount() })

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	if _, _, ok := b.edgeCombo(); !ok {
		t.Fatal("the combo gave up on a pool that has an edge and an SNI in it")
	}
	for _, p := range []*PeerPool{pp, sp} {
		got := p.current()
		p.mu.Lock()
		axis, at, chosen := p.axis, p.addrs[p.cur], p.chosen
		live := p.liveAddr()
		p.mu.Unlock()
		if at != got {
			t.Fatalf("%s: current() gave %q while the cursor names %q", axis, got, at)
		}
		if live == nil || live.s != at {
			t.Fatalf("%s: the carrier is reading %+v while the cursor names %q", axis, live, at)
		}
		if chosen != "" && chosen != at {
			t.Fatalf("%s: chosen=%q while the cursor names %q", axis, chosen, at)
		}
	}
}
