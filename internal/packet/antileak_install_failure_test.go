//go:build linux

package packet

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAntiLeakSurvivesAFailedInstall(t *testing.T) {
	defer func(mn, mx, lg time.Duration) {
		antiLeakRetryMin, antiLeakRetryMax, antiLeakLinger = mn, mx, lg
	}(antiLeakRetryMin, antiLeakRetryMax, antiLeakLinger)
	antiLeakRetryMin, antiLeakRetryMax = 20*time.Millisecond, 40*time.Millisecond
	antiLeakLinger = 20 * time.Millisecond

	const prev, next = "203.0.113.10", "203.0.113.20"

	t.Run("a failed re-scope keeps the working rule, then retries on its own", func(t *testing.T) {
		rec := &leakRecorder{}
		r := &Raw{profile: "udp", isClient: true, closeCh: make(chan struct{})}
		r.link = &directLink{r: r}
		r.leak.init(r.closeCh, rec.install)
		defer func() { close(r.closeCh); r.leak.teardown() }()

		r.leak.scope(net.ParseIP(prev).To4())
		if ev := rec.events(); len(ev) != 1 || ev[0] != "add "+prev {
			t.Fatalf("the first scope did not install: %v — the rest of this case would be vacuous", ev)
		}

		rec.setFail(true)
		r.leak.scope(net.ParseIP(next).To4())
		ev := rec.events()
		if evIndex(ev, "fail "+next) < 0 {
			t.Fatalf("the re-scope was never attempted: %v", ev)
		}
		if evIndex(ev, "del "+prev) >= 0 {
			t.Fatalf("the rule for %s was removed for an install that did not happen — the peer it covered is now leaking: %v", prev, ev)
		}
		r.leak.mu.Lock()
		cur := append(net.IP(nil), r.leak.curIP...)
		r.leak.mu.Unlock()
		if !cur.Equal(net.ParseIP(prev).To4()) {
			t.Fatalf("the installed scope is recorded as %v after a failed install, want %s — every later scope now short-circuits on it and the rules never go in", cur, prev)
		}

		rec.setFail(false)
		waitFor(t, 5*time.Second, "the carrier retried the install by itself", func() bool {
			return evIndex(rec.events(), "add "+next) >= 0
		})
		waitFor(t, 5*time.Second, "the displaced rule was removed after its linger", func() bool {
			return evIndex(rec.events(), "del "+prev) >= 0
		})
		ev = rec.events()
		add, del := evIndex(ev, "add "+next), evIndex(ev, "del "+prev)
		if add > del {
			t.Fatalf("the retry removed the old scope before installing the new one — the gap the install-before-remove order exists to close: %v", ev)
		}
	})

	t.Run("a partial install is rolled back rather than orphaned", func(t *testing.T) {
		var mu sync.Mutex
		var ev []string
		closeCh := make(chan struct{})
		a := &antiLeaker{}
		a.init(closeCh, func(peer net.IP) (func(), bool) {
			ip := peer.String()
			mu.Lock()
			ev = append(ev, "add "+ip)
			mu.Unlock()
			return func() {
				mu.Lock()
				ev = append(ev, "del "+ip)
				mu.Unlock()
			}, false
		})
		defer func() { close(closeCh); a.teardown() }()

		a.scope(net.ParseIP(next).To4())
		mu.Lock()
		got := append([]string(nil), ev...)
		mu.Unlock()
		if len(got) < 2 || got[0] != "add "+next || got[1] != "del "+next {
			t.Fatalf("the half-installed set was not rolled back: %v", got)
		}
		a.mu.Lock()
		cur := a.curIP
		a.mu.Unlock()
		if cur != nil {
			t.Errorf("a partial install was recorded as the live scope (%v)", cur)
		}
	})

	t.Run("a profile no kernel answers is a success, not a failed install", func(t *testing.T) {
		restore := iptablesRun
		iptablesRun = func(args []string) ([]byte, error) {
			t.Errorf("a quiet profile reached iptables: %v", args)
			return nil, nil
		}
		defer func() { iptablesRun = restore }()
		for _, p := range []string{"bare", "ipip", "gre", "esp"} {
			rm, ok := addRawDrop(testDst, p, "core42", 0, true, true)
			if rm != nil || !ok {
				t.Errorf("raw/%s: addRawDrop returned removal=%v ok=%v, want nil/true", p, rm != nil, ok)
			}
		}
	})

	t.Run("iptables refusing every rule is reported as a failure", func(t *testing.T) {
		restore := iptablesRun
		iptablesRun = func([]string) ([]byte, error) {
			return []byte("Another app is currently holding the xtables lock"), errors.New("exit status 4")
		}
		defer func() { iptablesRun = restore }()

		if rm, ok := addRawDrop(testDst, "udp", "core42", 0, true, false); rm != nil || ok {
			t.Errorf("raw/udp: addRawDrop returned removal=%v ok=%v, want nil/false", rm != nil, ok)
		}
	})

	t.Run("Close stops the pending retry", func(t *testing.T) {
		rec := &leakRecorder{fail: true}
		closeCh := make(chan struct{})
		a := &antiLeaker{}
		a.init(closeCh, rec.install)

		a.scope(net.ParseIP(next).To4())
		if evIndex(rec.events(), "fail "+next) < 0 {
			t.Fatal("no install was attempted, so no retry is owed and this case proves nothing")
		}
		close(closeCh)
		a.teardown()
		n := len(rec.events())
		time.Sleep(10 * antiLeakRetryMax)
		if got := rec.events(); len(got) != n {
			t.Errorf("a rule was still being installed after Close: %v", got[n:])
		}
	})
}
