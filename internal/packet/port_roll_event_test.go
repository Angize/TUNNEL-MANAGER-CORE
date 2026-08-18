package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// rollingPort is a raw client whose tuple is already silent, wired exactly as clientLoop wires it, with
// a status file so the events it writes can be read back.
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

// TestARollingPortSaysSoOncePerOutage is the whole reason this event needs a latch at all.
//
// The rung redraws the port every portSilence for as long as the tuple stays dead, so a line per roll
// would bury the burn and the re-handshake that come after it. And it cannot be de-duplicated on
// portDead going quiet, because a roll CLEARS lastAsk and sends a fresh one — portDead then reads false
// for a whole window while nothing has recovered at all. Only the tuple answering means recovery, which
// is what re-arms this.
func TestARollingPortSaysSoOncePerOutage(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour // the SCHEDULED roll must not fire: every roll here is a ladder step

	ka := 6 * time.Second // portSilence 3s
	r, path := rollingPort(t, ka)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano()) // this tuple hears nothing

	// The client loop keeps asking -- that is what dates the silence. A roll clears lastAsk, so without
	// this the tuple could be condemned exactly once and the latch would never be tested at all.
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

// TestTheNextOutageSaysSoAgain: the latch is per outage, not per tunnel. Only the tuple ANSWERING
// re-arms it — a roll must not, or the count goes straight back to one line per roll.
func TestTheNextOutageSaysSoAgain(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour

	r, path := rollingPort(t, 10*time.Second)
	cur := r.peer.Load().IP

	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())
	r.ask()
	r.rollSourcePort(true)
	r.rollSourcePort(true) // still the same outage
	if n := len(rollEvents(t, path)); n != 1 {
		t.Fatalf("first outage wrote %d events, want 1", n)
	}

	r.markRx(cur) // the tuple answered: the outage is over and the next one is news again
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())
	r.ask()
	r.rollSourcePort(true)
	if n := len(rollEvents(t, path)); n != 2 {
		t.Fatalf("a second outage wrote %d events in total, want 2 — the latch never re-armed", n)
	}
}

// TestTheScheduledRollIsSilent. It moves the port of a tunnel that is carrying perfectly well, to keep
// the tuple from being a fixed one. That is maintenance, not an event, and at one line per ~60s per raw
// tunnel it would flush the panel's whole 500-event ring on a hub in under half an hour.
func TestTheScheduledRollIsSilent(t *testing.T) {
	r, path := rollingPort(t, 10*time.Second)
	if !r.rollSourcePort(false) {
		t.Fatal("the redraw did not move the port")
	}
	if n := len(rollEvents(t, path)); n != 0 {
		t.Fatalf("the scheduled refresh wrote %d events, want none", n)
	}
}
