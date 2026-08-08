package packet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// The server's dead_after_secs must REACH the read deadline, not merely land in a field. Reading the
// field back passes on a tree where the value never touches a socket, and the window only matters if a
// silent peer is actually reaped on it: on tcp/ws that deadline IS the dead-detection window. So this
// drives readLoop, on a real TCP connection, against a peer that connects and then says nothing.
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

	// ...and the same carrier with a LONG window keeps waiting, so the case above cannot pass by
	// accident on a carrier that reaps everything quickly. The control sets the window explicitly
	// rather than leaning on the default: with one multiplier the default is 3x keepalive, which at
	// this test's 1s keepalive is the same 3s the case above configures -- it could no longer tell
	// the two apart. Setting it isolates the one variable that is supposed to matter.
	t.Run("with a long window the same carrier keeps waiting", func(t *testing.T) {
		took, err := run(t, func(b *TCP) { b.SetDeadAfter(30) })
		if err != nil {
			t.Fatalf("a 30s window reaped a silent peer after only %v (%v): then the test above proves nothing", took, err)
		}
		t.Logf("still waiting after %v, as a 30s window should", took)
	})
}
