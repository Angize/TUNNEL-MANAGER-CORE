//go:build linux

package packet

import (
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

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

				if 3*time.Second < dw/2 {
					t.Fatalf("no port-silence window, but %v would have fitted inside the dead window %v",
						3*time.Second, dw)
				}
				return
			}

			if ps >= dw/2 {
				t.Errorf("port silence %v is not comfortably inside the dead window %v", ps, dw)
			}

			if ps < 3*time.Second {
				t.Errorf("port silence %v would fire on an ordinary inbound gap", ps)
			}
		})
	}
}

func TestOnlyAnUnansweredAskCondemnsThePort(t *testing.T) {
	now := time.Now()
	past := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }

	for _, tc := range []struct {
		name string
		ka   time.Duration
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

func greenSession(t *testing.T, r *Raw) {
	t.Helper()
	sl, err := crypto.NewSealer(crypto.CipherChaCha, "port-refresh-psk-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	r.session.Store(&sealerBox{s: sl})
	if r.link == nil {

		r.link = &capturingLink{r: r}
	}
}

func TestTheLadderRollsOnScheduleAndOnlyAddsTheReactiveReason(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = 3 * time.Second

	r := &Raw{isClient: true, keepalive: 10 * time.Second, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
	greenSession(t, r)

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

	if len(seen) > 6 {
		t.Fatalf("%d ports in 7s with a %v schedule -- a carrying tuple is being condemned",
			len(seen), rawSportEvery)
	}
}

func TestADeadPathCondemnsOneTuplePerWindow(t *testing.T) {
	ka := 10 * time.Second
	ps := portSilence(ka)
	r := &Raw{isClient: true, keepalive: ka}
	r.peer.Store(&net.IPAddr{IP: testDst})

	base := time.Now()
	r.lastRxCur.Store(base.Add(-time.Minute).UnixNano())

	r.ask()
	first := r.lastAsk.Load()
	if first == 0 {
		t.Fatal("the first ask was not stamped")
	}

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

	r.lastAsk.Store(0)
	if r.portDead(base.Add(ps + 2*time.Second)) {
		t.Fatal("the fresh tuple was condemned on the previous one's silence: a roll every tick")
	}
	r.ask()
	second := r.lastAsk.Load()
	if second == 0 || second == first {
		t.Fatal("the new tuple never started its own clock")
	}
}

func TestTheLadderRollsOncePerWindowOnADeadPath(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour

	ka := 10 * time.Second
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: testDst})
	r.cliPort.Store(40000)
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
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		seen[r.cliPort.Load()] = true
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)
	close(r.closeCh)
	wait()

	if len(seen) < 2 {
		t.Fatalf("%d ports in 12s on a DEAD path: a retransmitted ask keeps resetting the clock, "+
			"so the tuple is never condemned", len(seen))
	}
	if len(seen) > 5 {
		t.Fatalf("%d ports in 12s with a %v window: the fresh tuple is being condemned on the "+
			"previous one's silence -- a roll every tick", len(seen), portSilence(ka))
	}
}

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

func TestAPoolProbingItsOtherEndpointDoesNotSaveADeadTuple(t *testing.T) {
	defer func(d time.Duration) { rawSportEvery = d }(rawSportEvery)
	rawSportEvery = time.Hour

	ka := 10 * time.Second
	cur, other := net.IPv4(10, 20, 0, 2), net.IPv4(10, 20, 0, 3)
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: cur})
	r.cliPort.Store(40000)
	r.lastRxCur.Store(time.Now().Add(-time.Minute).UnixNano())

	stop := make(chan struct{})
	go func() {
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
