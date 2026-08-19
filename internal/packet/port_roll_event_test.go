package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func rollingPort(t *testing.T, ka time.Duration) (*Raw, string) {
	t.Helper()
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.cliPort.Store(40000)
	path := filepath.Join(t.TempDir(), "core.status")
	r.SetStatusPath(path)
	return r, path
}

func rollEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	var out []coreEvent
	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "port-roll" {
			out = append(out, e)
		}
	}
	return out
}

func TestARollingPortSaysSoOncePerOutage(t *testing.T) {

	ka := 6 * time.Second
	r, path := rollingPort(t, ka)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				r.ask()
			}
		}
	}()

	wait := ladderBeat(r)
	seen := map[uint32]bool{}
	deadline := time.Now().Add(14 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	close(r.closeCh)
	wait()

	if len(seen) < 3 {
		t.Fatalf("only %d ports in 14s — the rung is not rolling, so this proves nothing", len(seen))
	}
	if ev := rollEvents(t, path); len(ev) != 1 {
		t.Fatalf("%d port-roll events for %d rolls in one outage, want exactly 1", len(ev), len(seen))
	}
}

func TestTheNextOutageSaysSoAgain(t *testing.T) {

	r, path := rollingPort(t, 10*time.Second)
	cur := r.peer.Load().IP

	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())
	r.ask()
	r.rollSourcePort()
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 1 {
		t.Fatalf("first outage wrote %d events, want 1", n)
	}

	r.markRx(cur)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())
	r.ask()
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 2 {
		t.Fatalf("a second outage wrote %d events in total, want 2 — the latch never re-armed", n)
	}
}
