package packet

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

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
		peer, err := net.Dial("tcp", ln.Addr().String())
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

		b := &TCP{idle: connIdle, ping: pingEvery}
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

	defer func(d time.Duration) { connIdle = d }(connIdle)
	connIdle = 3 * time.Second
	want := connIdle

	t.Run("the resolved window reaps the silent peer", func(t *testing.T) {
		took, err := run(t, func(*TCP) {})
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

	t.Run("with a long window the same carrier keeps waiting", func(t *testing.T) {
		took, err := run(t, func(b *TCP) { b.idle = 30 * time.Second })
		if err != nil {
			t.Fatalf("a 30s window reaped a silent peer after only %v (%v): then the test above proves nothing", took, err)
		}
		t.Logf("still waiting after %v, as a 30s window should", took)
	})
}
