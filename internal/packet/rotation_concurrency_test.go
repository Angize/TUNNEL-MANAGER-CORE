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
	run(func() { p.pinLandedOn("d1") })
	run(func() { p.pinCannotLand("d2") })
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
	if p.pinKey != "" && p.pinKey != got {
		t.Fatalf("pin is on %q but current() gave %q", p.pinKey, got)
	}
	if p.pinKey != "" && !p.health.healthy(p.pinKey) {
		t.Fatalf("the pinned endpoint %q came out of the storm burned", p.pinKey)
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
	b, p := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("s1", "s2"))

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
	run(func() { p.advance() })
	run(func() { p.advanceIP(); p.restoreIPs() })
	run(func() {
		low, high := b.livePairNow()
		if high != "" {
			b.rc.fail(b.rotateLowTCP, b.rotateHighTCP)
			_ = low
		}
	})
	run(func() {
		ip, sni, _ := p.current()
		b.pretendConnected(ip, sni.host)
	})
	run(func() { p.selectEntry("ip", "e2") })
	run(func() { p.pinLandedOn("e1", "s1") })
	run(func() { p.pinCannotLand("e2", "s2") })
	run(func() { p.clearBurn("sni", "s2") })
	run(func() { p.clearBurn("ip", "e3") })
	run(func() { _ = p.eligibleIPs() })
	run(func() { _ = p.isPinned() })

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	ip, sni, ok := p.current()
	if !ok {
		t.Fatal("current() gave up on a non-empty pool")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pinIP != "" && p.pinIP != ip {
		t.Fatalf("ip pin is on %q but current() gave %q", p.pinIP, ip)
	}
	if p.pinSNI != "" && p.pinSNI != sni.host {
		t.Fatalf("sni pin is on %q but current() gave %q", p.pinSNI, sni.host)
	}
	if p.pinIP != "" && !p.ipHealth.healthy(p.pinIP) {
		t.Fatalf("the pinned edge %q came out of the storm burned", p.pinIP)
	}
	if p.chosen != "" {
		at := activeLabel(p.ips[p.i%len(p.ips)], p.snis[p.j%len(p.snis)].host)
		if at != p.chosen {
			t.Fatalf("chosen=%q while the cursor is on %q", p.chosen, at)
		}
	}
}
