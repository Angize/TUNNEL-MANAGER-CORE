//go:build linux

package packet

import (
	"net"
	"testing"
	"time"
)

// About one rolled source port in eight has its RETURN direction blackholed: every packet the client
// sends still arrives, the peer answers every one of them, and not a single answer comes back. The
// client cannot see any of that -- all it has is silence -- and it used to sit on the dead 4-tuple until
// the scheduled roll came round, 42 to 78 seconds later. That is what carries a healthy tunnel past its
// dead window and into a re-handshake, on the same dead tuple, which cannot complete either.
//
// So an unanswered ASK condemns the tuple. The tests here pin what "unanswered" has to mean, because
// every cheaper definition is wrong in a way that either never fires or fires constantly.

func TestPortSilenceSitsBetweenAGapAndTheDeadWindow(t *testing.T) {
	old := deadMult
	defer func() { deadMult = old }()

	for _, tc := range []struct {
		name string
		mult int64
		ka   time.Duration
	}{
		{"the tightest setting the clamp allows", 2, 5 * time.Second},
		{"the default", 3, 5 * time.Second},
		{"the settings this fleet runs", 5, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadMult = tc.mult
			ps, dw := portSilence(tc.ka), deadWindow(tc.ka)
			// Far below the dead window, or the port is never discarded before the session is declared
			// stale over it -- which is the whole bug.
			if ps >= dw/2 {
				t.Errorf("port silence %v is not comfortably inside the dead window %v", ps, dw)
			}
			// ...and above any legitimate inbound gap. The largest gap measured on a live tunnel that
			// was carrying normally was 3.1s.
			if ps < 3*time.Second {
				t.Errorf("port silence %v would fire on an ordinary inbound gap", ps)
			}
		})
	}
}

// The three states a client can be in, and only the third may roll. Getting this wrong in the obvious
// way -- judging on lastRx alone -- rolls the port on every idle tunnel between keepalives.
func TestOnlyAnUnansweredAskCondemnsThePort(t *testing.T) {
	now := time.Now()
	ka := 10 * time.Second
	past := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }

	for _, tc := range []struct {
		name string
		ask  int64
		rx   int64
		want bool
	}{
		{"a fresh client that has asked nothing", 0, 0, false},
		{"idle: the last ping was answered, and no ping is due yet",
			past(30 * time.Second), past(30*time.Second - 70*time.Millisecond), false},
		{"a ping just went out and the answer is still in flight",
			past(100 * time.Millisecond), past(10 * time.Second), false},
		{"answered on the current tuple, however long ago",
			past(9 * time.Second), past(8 * time.Second), false},
		{"asked, and nothing came back for longer than any real gap",
			past(9 * time.Second), past(30 * time.Second), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Raw{isClient: true, keepalive: ka}
			r.lastAsk.Store(tc.ask)
			r.lastRx.Store(tc.rx)
			if got := r.portDead(now); got != tc.want {
				t.Fatalf("portDead = %v, want %v (silence window %v)", got, tc.want, portSilence(ka))
			}
		})
	}
}

// ask() is what makes the difference between "we heard nothing" and "we asked and heard nothing". A
// client with nowhere to send has asked no one, and must not condemn the port on its own silence.
func TestAskOnlyCountsWhenThereIsSomeoneToAnswer(t *testing.T) {
	r := &Raw{isClient: true, keepalive: 10 * time.Second}
	r.ask()
	if r.lastAsk.Load() != 0 {
		t.Error("a client with no peer stamped an ask: its own silence would condemn the port")
	}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.ask()
	if r.lastAsk.Load() == 0 {
		t.Fatal("a client with a peer did not stamp the ask, so no unanswered ping can ever be noticed")
	}

	s := &Raw{isClient: false, keepalive: 10 * time.Second}
	s.peer.Store(&net.IPAddr{IP: testDst})
	s.ask()
	if s.lastAsk.Load() != 0 {
		t.Error("the server stamped an ask -- it does not roll ports and owes no one an answer")
	}
}

// The reactive roll must not replace the scheduled one. A tuple that is carrying perfectly still has to
// keep moving: a source port that only ever changes when something breaks is a port that stops moving
// on a healthy tunnel, which is exactly the fixed 4-tuple the rotation exists to avoid.
func TestAHealthyTupleStillRollsOnSchedule(t *testing.T) {
	r := &Raw{isClient: true, keepalive: 10 * time.Second}
	r.peer.Store(&net.IPAddr{IP: testDst})
	now := time.Now()
	r.lastAsk.Store(now.Add(-9 * time.Second).UnixNano())
	r.lastRx.Store(now.Add(-8 * time.Second).UnixNano()) // answered: nothing outstanding
	if r.portDead(now) {
		t.Fatal("a carrying tuple was condemned")
	}
	// The scheduled deadline is what has to move it, and it is jittered rather than exact -- a port that
	// changes on a clock is itself the period a DPI locks onto.
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[jitterFrac(rawSportEvery)] = true
	}
	if len(seen) < 100 {
		t.Fatalf("the scheduled interval took only %d distinct values in 200 draws", len(seen))
	}
}
