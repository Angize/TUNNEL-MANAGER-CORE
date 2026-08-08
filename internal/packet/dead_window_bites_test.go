package packet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// The resolved dead window must REACH the read deadline, not merely land in a field. Reading the field
// back passes on a tree where the value never touches a socket, and the window only matters if a silent
// peer is actually reaped on it: on tcp/ws that deadline IS the dead-detection window. So this drives
// readLoop, on a real TCP connection, against a peer that connects and then says nothing. It runs on the
// SERVER end, which is where the window used to be left at a default while the client self-healed.
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

		b := &TCP{keepalive: keepalive, idle: deadWindow(keepalive)}
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

	want := deadWindow(keepalive)

	t.Run("the resolved window reaps the silent peer", func(t *testing.T) {
		took, err := run(t, func(*TCP) {}) // the window the constructor resolved, untouched
		if err == nil {
			t.Fatalf("the read loop was still waiting after %v: the resolved window never reached the socket, so this end waits out the kernel's own TCP keepalive while the other self-heals in %v", took, want)
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the loop ended with %v after %v; want a read deadline", err, took)
		}
		if took > want+3*time.Second {
			t.Errorf("the silent peer was reaped after %v, not the resolved %v — the window in force is not the one keepalive sizes", took.Round(100*time.Millisecond), want)
		}
		t.Logf("reaped after %v (window %v)", took.Round(100*time.Millisecond), want)
	})

	// ...and the same carrier with a LONG window keeps waiting, so the case above cannot pass by
	// accident on a carrier that reaps everything quickly. It is set on the field rather than derived,
	// because a keepalive high enough to derive 30s would put the case above out of the test's budget.
	t.Run("with a long window the same carrier keeps waiting", func(t *testing.T) {
		took, err := run(t, func(b *TCP) { b.idle = 30 * time.Second })
		if err != nil {
			t.Fatalf("a 30s window reaped a silent peer after only %v (%v): then the test above proves nothing", took, err)
		}
		t.Logf("still waiting after %v, as a 30s window should", took)
	})
}
