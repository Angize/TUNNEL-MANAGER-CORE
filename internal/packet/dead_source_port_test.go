//go:build linux

package packet

import (
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
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
// way -- judging on lastRxCur alone -- rolls the port on every idle tunnel between keepalives.
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
			r.lastRxCur.Store(tc.rx)
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

// ladderBeat runs the ladder's REAL poller over a raw client's port rung, wired exactly as clientLoop
// wires it, and returns a func that waits for it to stop (the caller closes r.closeCh).
//
// The port used to move on a goroutine of the carrier's own. It does not any more, so a test that drove
// that loop would be describing a program that no longer exists -- this drives the one that does.
func ladderBeat(r *Raw) (wait func()) {
	rc := newRotationController(nil, nil)
	rc.port.setRoll(r.rollSourcePort)
	rc.port.setRefresh(r.portDead, func() bool { return r.sealer() != nil }, rawSportEvery)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPinPoll(rc, r.closeCh, func() {}, func() {}, func(bool) {}, func(bool) {}, nil, func() int64 { return 0 })
	}()
	return func() { <-done }
}

// greenSession gives a bare test carrier a real session, so `ready` is true and the SCHEDULED refresh
// is allowed to fire. Without one only the reactive trigger can move the port.
func greenSession(t *testing.T, r *Raw) {
	t.Helper()
	sl, err := crypto.NewSealer(crypto.CipherChaCha, "port-refresh-psk-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	r.session.Store(&sealerBox{s: sl})
	if r.link == nil {
		// With a session the post-roll ping really is sealed and sent, so it needs somewhere to go.
		r.link = &capturingLink{r: r}
	}
}

// The reactive roll must never CONDEMN a carrying tuple -- it may only add a reason to roll, never
// remove one. A source port that changed only when something broke would stop moving on a healthy
// tunnel, which is the fixed 4-tuple the rotation exists to avoid.
//
// Driven through the ladder's REAL beat, because the condition and the code that reads it are two
// different things and only one of them is the subject: a beat that ignored portDead, or one that
// rolled every tick, both pass a check written against portDead alone.
func TestTheLadderRollsOnScheduleAndOnlyAddsTheReactiveReason(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = 3 * time.Second // the beat ticks at 1s, so this is a few scheduled rolls in the run

	r := &Raw{isClient: true, keepalive: 10 * time.Second, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
	greenSession(t, r) // the scheduled refresh is taken only on a green tunnel
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
			r.lastRxCur.Store(n + 1)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	wait := ladderBeat(r)
	seen := map[uint32]bool{}
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(50 * time.Millisecond)
	}
	close(r.closeCh)
	wait()

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
	r.lastRxCur.Store(base.Add(-time.Minute).UnixNano()) // last heard a minute ago: the path is down

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

	// The roll clears it, exactly as the ladder's beat does, and the fresh tuple gets its own full window --
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

// The same claim, through the ladder's REAL beat. The case above pins the semantics by hand, so it
// stays green if the beat never applies them -- and the beat is where both mistakes actually live.
//
// A client re-handshaking on a dead path: no session, so the post-roll ping cannot go out and only the
// ~1s init retransmit re-stamps. No session also means the SCHEDULE is off, which is the point here --
// every roll below is the reactive one. Rolls must come one per window, not one per tick.
func TestTheLadderRollsOncePerWindowOnADeadPath(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour // the SCHEDULED roll must not fire: every roll here is the reactive one

	ka := 10 * time.Second // portSilence 5s
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano()) // heard nothing for a minute

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

	wait := ladderBeat(r)

	seen := map[uint32]bool{}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)
	close(r.closeCh)
	wait()

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

// A destination-rotation pool keeps ONE session across every endpoint, so a frame from the endpoint we
// are NOT on opens under that session and is genuinely inbound. It proves the session is alive. It
// proves nothing about the tuple we are on, and only the tuple's own clock may hear it.
func TestOnlyTheCurrentDestinationAnswersForItsOwnTuple(t *testing.T) {
	cur, other := net.IPv4(10, 20, 0, 2), net.IPv4(10, 20, 0, 3)
	r := &Raw{isClient: true, keepalive: 10 * time.Second}
	r.peer.Store(&net.IPAddr{IP: cur})

	r.markRx(other)
	if r.lastRxCur.Load() != 0 {
		t.Fatal("a reply from the endpoint we are NOT on answered on behalf of the tuple we are on")
	}

	r.markRx(cur)
	if r.lastRxCur.Load() == 0 {
		t.Fatal("the current destination's own reply did not answer its tuple: a carrying port would roll")
	}
}

// ...and the same claim through the ladder's REAL beat, which is where it decides anything. A tuple whose
// return direction is gone, while the pool goes on proving its OTHER endpoint alive, must still be
// condemned. One shared clock made the reactive roll unreachable on precisely the tunnels that have
// somewhere else to roll to.
func TestAPoolProbingItsOtherEndpointDoesNotSaveADeadTuple(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour // the SCHEDULED roll must not fire: every roll here is the reactive one

	ka := 10 * time.Second // portSilence 5s
	cur, other := net.IPv4(10, 20, 0, 2), net.IPv4(10, 20, 0, 3)
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: cur})
	r.cliPort.Store(40000)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano()) // the tuple we are on hears nothing

	stop := make(chan struct{})
	go func() { // our ask keeps going out, and the pool keeps retesting the endpoint we are NOT on
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
				r.ask()
				r.markRx(other)
			}
		}
	}()

	wait := ladderBeat(r)

	seen := map[uint32]bool{}
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)
	close(r.closeCh)
	wait()

	if len(seen) < 2 {
		t.Fatalf("%d port(s) in 12s: the other endpoint's replies answered for the dead tuple, so the "+
			"reactive roll never fired and only the schedule could recover it", len(seen))
	}
	if len(seen) > 5 {
		t.Fatalf("%d ports in 12s with a %v window: rolling far faster than one per window",
			len(seen), portSilence(ka))
	}
}
