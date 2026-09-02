package packet

import (
	"fmt"
	"net"
	"path/filepath"
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
// the ONLY thing that can move the pool is the scheduled tick: a plain disconnect on a pp client takes
// the endRound branch, never pool.advance().
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
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

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

// The arithmetic on its own, so a future edit that keeps the deadline but re-arms it in the wrong place
// is caught without a 14-second test.
func TestARotationDeadlineIsNotRestartedByArming(t *testing.T) {
	b := &TCP{rotate: time.Minute}
	if d := b.rotateIn(b.rotate); d > time.Minute || d < 59*time.Second {
		t.Fatalf("the first arming asked for %v, want the whole interval", d)
	}
	b.rotAt.Add(-int64(40 * time.Second))
	d := b.rotateIn(b.rotate)
	if d > 21*time.Second {
		t.Fatalf("after 40s of the minute had passed a reconnect armed for %v; the elapsed time was "+
			"thrown away", d)
	}
	b.rotAt.Add(-int64(30 * time.Second))
	if d := b.rotateIn(b.rotate); d > time.Millisecond {
		t.Fatalf("a deadline that passed during an outage armed for %v, want an immediate fire", d)
	}
	b.rotateFrom(b.rotate)
	if d := b.rotateIn(b.rotate); d < 59*time.Second {
		t.Fatalf("a rotation that fired left the next deadline at %v, want a fresh interval", d)
	}
}
