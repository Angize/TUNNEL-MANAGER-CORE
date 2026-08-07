package packet

import (
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// In production nothing drives a pool from one goroutine. The carrier's dial loop asks current(); the
// 1s pin poll delivers the node's verdicts and the panel's pins; the rotation timer walks it; the retest
// scheduler moves the ladder; and writeStatus runs from all of them. The pools carry their own mutexes,
// so the question is not whether a field tears -- the race detector answers that -- but whether the
// INVARIANTS still hold when those callers interleave, which no single-goroutine test can ask.

// TestPeerPoolUnderConcurrentDrivers hammers one direct pool from every caller it really has.
func TestPeerPoolUnderConcurrentDrivers(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	p := NewPeerPool([]string{"d1", "d2", "d3"}, true, 0, filepath.Join(t.TempDir(), "d.json"))

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

	run(func() { p.current() })                 // the dial loop
	run(func() { p.fail() })                    // a carrier-driven failover
	run(func() { p.rotateOnce() })              // the proactive timer
	run(func() { p.selectEntry("d2") })         // the panel's pin
	run(func() { p.pinLandedOn("d1") })         // a carrier landing somewhere the pin did not ask for
	run(func() { p.pinAttemptFailed("d2") })    // the pin's own evidence
	run(func() { p.clearBurn("d3") })           // a tun-probe OK
	run(func() { p.burnNamed("d3") })           // a keyed tun-probe fail
	run(func() { p.probeAllNow() })             // the panel's "probe now"
	run(func() { _ = p.eligibleCount() })       // the odometer's lap sizing
	run(func() { p.keepCursorOn(p.current()) }) // make-before-break putting the cursor back

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	// The pool must still be internally consistent, whatever order those landed in.
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

// TestEdgePoolUnderConcurrentDrivers is the same storm on the two-axis pool, where the verdict path and
// the standby builder move the SAME cursor from different goroutines.
func TestEdgePoolUnderConcurrentDrivers(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1", "s2"), true, filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{pool: p}

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
	run(func() { p.aimStandby() })
	run(func() {
		ip, sni := p.activeCombo()
		if ip != "" {
			b.burnAdvanceWS(ip, sni)
		}
	})
	run(func() {
		ip, sni, _ := p.current()
		p.setActive(activeLabel(ip, sni.host))
	})
	run(func() { p.selectEntry("ip", "e2") })
	run(func() { p.pinApplied("e1", "s1") })
	run(func() { p.pinAttemptFailed("e2", "s2") })
	run(func() { p.clearBurn("sni", "s2") })
	run(func() { p.retestResult("ip", "e3", true) })
	run(func() { _ = p.eligibleSNIs() })
	run(func() { _ = p.hasEligibleEdgeOtherThan("e1 · s1") })

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
