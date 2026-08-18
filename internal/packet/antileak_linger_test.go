//go:build linux

package packet

import (
	"net"
	"testing"
	"time"
)

func TestTheAntiLeakLingersOnTheAddressItJustLeft(t *testing.T) {
	defer func(d time.Duration) { antiLeakLinger = d }(antiLeakLinger)
	antiLeakLinger = 150 * time.Millisecond

	const first, second = "203.0.113.10", "203.0.113.20"

	t.Run("the rule for the address we left stays in, then goes", func(t *testing.T) {
		rec := &leakRecorder{}
		closeCh := make(chan struct{})
		var leak antiLeaker
		leak.init(closeCh, rec.install)
		defer func() { close(closeCh); leak.teardown() }()

		leak.scope(net.ParseIP(first).To4())
		leak.scope(net.ParseIP(second).To4())
		ev := rec.events()
		if evIndex(ev, "add "+second) < 0 {
			t.Fatalf("the rotation did not install the new scope: %v", ev)
		}
		if evIndex(ev, "del "+first) >= 0 {
			t.Fatalf("the rule for %s was removed the instant the scope moved; the frames still in flight "+
				"from it are answered by the kernel: %v", first, ev)
		}
		waitFor(t, 5*time.Second, "the left-behind rule was removed once the frames could no longer be in flight",
			func() bool { return evIndex(rec.events(), "del "+first) >= 0 })
	})

	t.Run("rotating back adopts the rule instead of installing a second", func(t *testing.T) {
		rec := &leakRecorder{}
		closeCh := make(chan struct{})
		var leak antiLeaker
		leak.init(closeCh, rec.install)
		defer func() { close(closeCh); leak.teardown() }()

		leak.scope(net.ParseIP(first).To4())
		leak.scope(net.ParseIP(second).To4())
		leak.scope(net.ParseIP(first).To4())
		ev := rec.events()
		adds := 0
		for _, e := range ev {
			if e == "add "+first {
				adds++
			}
		}
		if adds != 1 {
			t.Errorf("%s was installed %d times; the rule was still in, so the second is a duplicate: %v",
				first, adds, ev)
		}
		if evIndex(ev, "del "+first) >= 0 {
			t.Errorf("the rule we rotated back onto was removed anyway: %v", ev)
		}

		waitFor(t, 5*time.Second, "the rule for the address left behind was removed",
			func() bool { return evIndex(rec.events(), "del "+second) >= 0 })
	})

	t.Run("Close leaves nothing behind", func(t *testing.T) {
		rec := &leakRecorder{}
		closeCh := make(chan struct{})
		var leak antiLeaker
		leak.init(closeCh, rec.install)

		leak.scope(net.ParseIP(first).To4())
		leak.scope(net.ParseIP(second).To4())
		close(closeCh)
		leak.teardown()
		for _, ip := range []string{first, second} {
			if evIndex(rec.events(), "del "+ip) < 0 {
				t.Errorf("teardown left the rule for %s on the host: %v", ip, rec.events())
			}
		}
	})

	t.Run("the left-behind rules are bounded", func(t *testing.T) {
		rec := &leakRecorder{}
		closeCh := make(chan struct{})
		var leak antiLeaker
		leak.init(closeCh, rec.install)
		defer func() { close(closeCh); leak.teardown() }()

		for i := 0; i < 12; i++ {
			leak.scope(net.IPv4(203, 0, 113, byte(40+i)).To4())
		}
		leak.mu.Lock()
		n := len(leak.pending)
		leak.mu.Unlock()
		if n > antiLeakMaxLinger {
			t.Errorf("%d rule sets are waiting to be removed, more than the %d bound", n, antiLeakMaxLinger)
		}
		ev := rec.events()
		live, gone := 0, 0
		for _, e := range ev {
			if len(e) > 4 && e[:4] == "add " {
				live++
			}
			if len(e) > 4 && e[:4] == "del " {
				gone++
			}
		}
		if live-gone > antiLeakMaxLinger+1 {
			t.Errorf("%d rule sets are installed on the host after 12 rotations", live-gone)
		}

	})
}
