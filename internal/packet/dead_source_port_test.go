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
		{"a keepalive short enough to squeeze the floor out", 2, 1 * time.Second},
		{"...and one just above it", 3, 4 * time.Second},
		{"the tightest multiplier the clamp allows", 2, 5 * time.Second},
		{"the default", 3, 5 * time.Second},
		{"the settings this fleet runs", 5, 10 * time.Second},
		{"a very long window", 100, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadMult = tc.mult
			ps, dw := portSilence(tc.ka), deadWindow(tc.ka)
			if ps == 0 {
				// No window fits. That is only allowed when the two rules genuinely collide -- asserting
				// it here rather than accepting any zero, or a bug that returned zero always would read
				// as a pass on every row.
				if 3*time.Second < dw/2 {
					t.Fatalf("no port-silence window, but %v would have fitted inside the dead window %v",
						3*time.Second, dw)
				}
				return
			}
			// Well inside the dead window, or the port is never discarded before the session is declared
			// stale over it -- which is the whole bug.
			if ps >= dw/2 {
				t.Errorf("port silence %v is not comfortably inside the dead window %v", ps, dw)
			}
			// ...and above any legitimate inbound gap. The largest measured on a live tunnel that was
			// carrying normally was 3.1s.
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
	past := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }

	for _, tc := range []struct {
		name string
		ka   time.Duration // 0 = the default 10s
		ask  int64
		rx   int64
		want bool
	}{
		{"a fresh client that has asked nothing", 0, 0, 0, false},
		{"idle: the last ping was answered, and no ping is due yet", 0,
			past(30 * time.Second), past(30*time.Second - 70*time.Millisecond), false},
		{"a ping just went out and the answer is still in flight", 0,
			past(100 * time.Millisecond), past(10 * time.Second), false},
		{"answered on the current tuple, however long ago", 0,
			past(9 * time.Second), past(8 * time.Second), false},
		{"asked, and nothing came back for longer than any real gap", 0,
			past(9 * time.Second), past(30 * time.Second), true},
		// A keepalive short enough that no window fits inside the dead window. Without the guard,
		// "unanswered for longer than zero" is true on every tick and the port rolls once a second.
		{"the same silence, but no window fits at all", time.Second,
			past(9 * time.Second), past(30 * time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ka := tc.ka
			if ka == 0 {
				ka = 10 * time.Second
			}
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

// The reactive roll must never CONDEMN a carrying tuple -- it may only add a reason to roll, never
// remove one. A source port that changed only when something broke would stop moving on a healthy
// tunnel, which is the fixed 4-tuple the rotation exists to avoid.
//
// Driven through the REAL sportLoop, because the condition and the loop that reads it are two different
// things and only one of them is the subject: a loop that ignored portDead, or one that rolled on every
// tick, both pass a check written against portDead alone.
func TestTheLoopRollsOnScheduleAndOnlyAddsTheReactiveReason(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = 3 * time.Second // the loop ticks at 1s, so this is a few scheduled rolls in the run

	r := &Raw{isClient: true, keepalive: 10 * time.Second, profile: "tcp", closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
	// A tuple that is carrying: every ask answered, so portDead is false for the whole run.
	go func() {
		for {
			select {
			case <-r.closeCh:
				return
			default:
			}
			n := time.Now().UnixNano()
			r.lastAsk.Store(n)
			r.lastRx.Store(n + 1)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); r.sportLoop() }()
	seen := map[uint32]bool{}
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(50 * time.Millisecond)
	}
	close(r.closeCh)
	<-done // the loop still READS rawSportEvery, and the deferred restore WRITES it: -race calls that
	// what it is. A solo run passed six times in a row before the broad run caught it.

	if len(seen) < 2 {
		t.Fatalf("a carrying tuple never rolled in 7s with a %v schedule: the reactive check "+
			"replaced the scheduled roll instead of adding to it", rawSportEvery)
	}
	// ...and not on every tick either, which is what a portDead that ignored the ask would do.
	if len(seen) > 6 {
		t.Fatalf("%d ports in 7s with a %v schedule -- a carrying tuple is being condemned",
			len(seen), rawSportEvery)
	}
}

// A dead path condemns ONE tuple per window, not one per tick. Both ways of getting this wrong look
// reasonable in isolation:
//
//   - a retransmitted ask that overwrites the stamp resets the clock every second, and the tuple is
//     never condemned however dead it is;
//   - a stamp that survives the roll dates the NEW tuple's silence from the OLD one's evidence, and
//     every following tick condemns a port that has not had a moment to answer.
//
// A client re-handshaking on a dead path hits both at once: sendInit retransmits about once a second,
// and the post-roll ping cannot go out at all because there is no session to seal it.
func TestADeadPathCondemnsOneTuplePerWindow(t *testing.T) {
	ka := 10 * time.Second
	ps := portSilence(ka) // 5s
	r := &Raw{isClient: true, keepalive: ka}
	r.peer.Store(&net.IPAddr{IP: testDst})

	base := time.Now()
	r.lastRx.Store(base.Add(-time.Minute).UnixNano()) // last heard a minute ago: the path is down

	r.ask() // the first unanswered ask dates the silence
	first := r.lastAsk.Load()
	if first == 0 {
		t.Fatal("the first ask was not stamped")
	}
	// ...and the handshake retransmits keep coming.
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Millisecond)
		r.ask()
	}
	if r.lastAsk.Load() != first {
		t.Fatal("a retransmit overwrote the first unanswered ask: the clock restarts every second " +
			"and the tuple is never condemned")
	}

	if r.portDead(base.Add(ps - time.Second)) {
		t.Error("condemned before the window was up")
	}
	if !r.portDead(base.Add(ps + time.Second)) {
		t.Fatal("a whole window of unanswered asks did not condemn the tuple")
	}

	// The roll clears it, exactly as sportLoop does, and the fresh tuple gets its own full window --
	// even though no ping could go out to re-stamp it (no session).
	r.lastAsk.Store(0)
	if r.portDead(base.Add(ps + 2*time.Second)) {
		t.Fatal("the fresh tuple was condemned on the previous one's silence: a roll every tick")
	}
	r.ask() // whatever goes out next on the new tuple -- a ping, or the next init retransmit
	second := r.lastAsk.Load()
	if second == 0 || second == first {
		t.Fatal("the new tuple never started its own clock")
	}
}

// The same claim, through the REAL sportLoop. The case above pins the semantics by hand, so it stays
// green if the loop never applies them -- and the loop is where both mistakes actually live.
//
// A client re-handshaking on a dead path: no session, so the loop's post-roll ping cannot go out, and
// only the ~1s init retransmit re-stamps. Rolls must come one per window, not one per tick.
func TestTheLoopRollsOncePerWindowOnADeadPath(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour // the SCHEDULED roll must not fire: every roll here is the reactive one

	ka := 10 * time.Second // portSilence 5s
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
	r.lastRx.Store(time.Now().Add(-time.Minute).UnixNano()) // heard nothing for a minute

	stop := make(chan struct{})
	go func() { // the handshake retransmit, ~1s apart like the real one
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				r.ask()
			}
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); r.sportLoop() }()

	seen := map[uint32]bool{}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)
	close(r.closeCh)
	<-done

	// 12s at one roll per 5s window: the starting port plus two, maybe three. A loop that condemns the
	// fresh tuple on the old one's evidence rolls every tick and lands near a dozen; one whose clock is
	// reset by each retransmit never rolls at all and lands at one.
	if len(seen) < 2 {
		t.Fatalf("%d ports in 12s on a DEAD path: a retransmitted ask keeps resetting the clock, "+
			"so the tuple is never condemned", len(seen))
	}
	if len(seen) > 5 {
		t.Fatalf("%d ports in 12s with a %v window: the fresh tuple is being condemned on the "+
			"previous one's silence -- a roll every tick", len(seen), portSilence(ka))
	}
}
