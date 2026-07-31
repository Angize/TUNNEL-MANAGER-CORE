package packet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// The server's dead_after_secs must REACH the read deadline, not merely land in a field.
//
// TestServerHonoursDeadAfter next door sets srv.idle through SetDeadAfter and then reads srv.idle
// back. That passes on the pre-fix tree, because SetDeadAfter was never what was gated — the role
// gate was at the call site — and it says nothing about whether the number ever reaches a socket.
// The window only matters if a silent peer is actually reaped on it: on tcp/ws that deadline IS the
// dead-detection window, and while the server kept its ~60s default, half the tunnel self-healed at
// the operator's speed and half did not.
//
// So this drives readLoop — the real loop, on a real TCP connection, against a peer that connects
// and then says nothing — and measures when it gives up.
func TestTheServersDeadWindowReallyReapsASilentPeer(t *testing.T) {
	const keepalive = time.Second

	run := func(t *testing.T, apply func(*TCP)) (time.Duration, error) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		accepted := make(chan net.Conn, 1)
		go func() {
			c, aerr := ln.Accept()
			if aerr == nil {
				accepted <- c
			}
		}()
		peer, err := net.Dial("tcp", ln.Addr().String()) // connects, then stays silent forever
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer peer.Close()

		var srv net.Conn
		select {
		case srv = <-accepted:
		case <-time.After(3 * time.Second):
			t.Fatal("the listener never accepted")
		}
		defer srv.Close()

		b := &TCP{keepalive: keepalive, idle: idleFor(keepalive)}
		apply(b)

		done := make(chan error, 1)
		t0 := time.Now()
		go func() { done <- b.readLoop(b.newFramer(srv)) }()
		select {
		case rerr := <-done:
			return time.Since(t0), rerr
		case <-time.After(12 * time.Second):
			return 12 * time.Second, nil
		}
	}

	t.Run("with dead_after_secs set, the silent peer is reaped on it", func(t *testing.T) {
		took, err := run(t, func(b *TCP) { b.SetDeadAfter(3) })
		if err == nil {
			t.Fatalf("the read loop was still waiting after %v: dead_after_secs never reached the socket, so this end keeps its ~60s default while the other self-heals in 3s", took)
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the loop ended with %v after %v; want a read deadline", err, took)
		}
		if took > 6*time.Second {
			t.Errorf("the silent peer was reaped after %v, not the configured 3s — the window in force is not the one the operator set", took.Round(100*time.Millisecond))
		}
		t.Logf("reaped after %v", took.Round(100*time.Millisecond))
	})

	// ...and without it the default really is long, so the case above cannot pass by accident on a
	// carrier that reaps everything quickly.
	t.Run("without it, the default window is far longer", func(t *testing.T) {
		took, err := run(t, func(b *TCP) {})
		if err != nil {
			t.Fatalf("the default window reaped a silent peer after only %v (%v): then the test above proves nothing", took, err)
		}
		t.Logf("still waiting after %v, as the ~60s default should", took)
	})
}
