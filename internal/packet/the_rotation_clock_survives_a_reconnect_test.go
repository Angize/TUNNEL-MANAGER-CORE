package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// For udp/raw the scheduled rotation is an absolute deadline on the controller: newRotationController
// sets rotateAt = now + interval and proactive() re-arms it from the wall clock every time it fires, so
// the interval means what the operator set no matter what the connection is doing.
//
// For tcp/ws it was a per-connection time.AfterFunc created inside the dial loop AFTER a successful
// connect, and stopped when that connection died. Nothing persisted the deadline, so every reconnect
// threw the elapsed time away and started the interval over. A tunnel whose carrier churns more often
// than the interval -- a CDN resetting, a DPI box killing the flow, exactly the tunnels that most need
// to move -- never rotated at all, and the panel showed no event because none happened.
//
// The two ends of this test are one listener with two addresses and a client whose pool holds both, so
// the ONLY thing that can move the pool is the scheduled tick: nothing here writes a verdict, and a
// disconnect on its own never walks a direct pool -- only the one-second cmdPollTick calls into it.
func TestTheScheduledRotationSurvivesAChurningCarrier(t *testing.T) {
	const psk = "a-psk-for-the-rotation-clock"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "rcsrv")
	cliDev, _ := tunPair(t, "rccli")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := ListenTCP([]string{a1, a2}, srvDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(a1, cliDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, 3*time.Second))
	cli.SetStatusPath(runningStatusPath(t, cli))

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(10 * time.Second)
	for cli.curConn.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("the client never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := cli.pp.current()
	moves := 0
	last := start
	stop := time.Now().Add(14 * time.Second)
	for time.Now().Before(stop) {
		time.Sleep(700 * time.Millisecond)
		if cc := cli.curConn.Load(); cc != nil {
			(*cc).Close()
		}
		if now := cli.pp.current(); now != last {
			moves++
			last = now
		}
	}
	if moves < 2 {
		t.Fatalf("the carrier was torn down every 700ms for 14s with a 3s rotation interval and the pool "+
			"moved %d times (still on %s) — the deadline is being thrown away on every reconnect, so the "+
			"operator's interval never arrives", moves, last)
	}
	t.Logf("14s of 700ms churn, 3s interval: %d rotations", moves)
}

// The arithmetic on its own, so a future edit that keeps the deadline but re-arms it in the wrong
// place is caught without a 14-second test. There is one clock for every carrier now: bind() arms
// rotationController.rotateAt from the pool's own interval, and proactive() is the production line the
// ticker calls with an injected `now`, not a stand-in for it.
func TestARotationDeadlineIsNotRestartedByArming(t *testing.T) {
	rc := newRotationController(NewPeerPool([]string{"d1", "d2"}, time.Minute), nil)
	fired := 0
	rot := func(bool) { fired++ }
	t0 := time.Now()

	rc.proactive(rot, rot, t0)
	if fired != 0 {
		t.Fatal("the first tick came due immediately; arming must put the deadline a whole interval out")
	}
	rc.proactive(rot, rot, t0.Add(59*time.Second))
	if fired != 0 {
		t.Fatal("59s into a one-minute interval the deadline was already due")
	}
	rc.proactive(rot, rot, t0.Add(time.Minute+time.Second))
	if fired != 1 {
		t.Fatalf("a minute of a one-minute interval passed and the deadline never came due (fired=%d)", fired)
	}

	rc.proactive(rot, rot, t0.Add(time.Minute+30*time.Second))
	if fired != 1 {
		t.Fatalf("a rotation that fired did not start a fresh interval (fired=%d)", fired)
	}
	rc.proactive(rot, rot, t0.Add(10*time.Minute))
	if fired != 2 {
		t.Fatalf("a deadline that passed during an outage was thrown away instead of firing late (fired=%d)", fired)
	}
}

// A pool with no interval never arms a deadline at all, so the shared ticker cannot fire on it.
func TestAPoolWithNoIntervalArmsNoDeadline(t *testing.T) {
	rc := newRotationController(NewPeerPool([]string{"d1", "d2"}, 0), nil)
	rc.mu.Lock()
	at := rc.rotateAt
	rc.mu.Unlock()
	if !at.IsZero() {
		t.Fatalf("rotation is off and the deadline is %v", at)
	}
	fired := 0
	rc.proactive(func(bool) { fired++ }, func(bool) { fired++ }, time.Now().Add(time.Hour))
	if fired != 0 {
		t.Fatalf("an hour later a carrier with rotation off rotated %d times", fired)
	}
}

// The clock is a standing ticker now, not a timer created after a successful connect, so the interval
// runs while the carrier is DOWN. Before, a pool whose current entry was black-holed was dialled for
// ever: no connection meant no timer meant no rotation, and only the node's tun probe could move it.
// Both addresses here refuse, so the ONLY thing that can move the cursor is the scheduled tick.
func TestTheScheduledRotationRunsWhileTheCarrierIsDown(t *testing.T) {
	cliDev, _ := tunPair(t, "rcdown")

	dead := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := l.Addr().String()
		l.Close()
		return a
	}
	a1, a2 := dead(), dead()

	cli, err := DialTCP(a1, cliDev, false, true, "a-psk-for-the-down-clock", "aes-256-gcm", false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	cli.SetStatusPath(runningStatusPath(t, cli))
	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, 2*time.Second))

	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	start := cli.pp.current()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if cli.curConn.Load() != nil {
			t.Fatal("setup: something accepted; both addresses must refuse for this test to mean anything")
		}
		if cli.pp.current() != start {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("12s with a 2s rotation interval and the pool never left %s. Nothing ever connected, so "+
		"the deadline only exists if the clock is standing -- a tunnel pointed at a black-holed "+
		"endpoint has no other way off it without the node", start)
}
