//go:build linux

package packet

import (
	"net"
	"testing"
	"time"
)

// TestDialLoopBurnsOnHandshakeFailure guards the destination pool against the interference shape this
// fleet actually meets: a DPI that lets the TCP handshake complete and then kills the payload, so the
// connect SUCCEEDS and the CORE handshake fails.
//
// dialLoop attributes a failed DIAL (burn + advance) but for a long time did nothing at all on a failed
// handshake — it fell straight through to the reconnect backoff. The pool therefore never moved and the
// client re-dialed the SAME blocked endpoint forever: destination rotation was inert for the one failure
// mode it exists to escape.
//
// The listener here accepts every connection and immediately closes it, which is exactly that shape. Both
// pool endpoints point at it, so the test never depends on an unroutable address (that would fail at DIAL
// and exercise the branch that already worked).
func TestDialLoopBurnsOnHandshakeFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { // accept, then drop before a single core frame is exchanged
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	addr := ln.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	second := net.JoinHostPort("127.0.0.2", port) // a loopback alias, same listener

	dev, _ := tunPair(t, "hsburn")
	b := &TCP{dev: dev, cryptoOn: true, cipher: "aes-256-gcm", psk: "handshake-burn-psk-abcdefghijkl",
		keepalive: time.Second, idle: idleFor(time.Second), isClient: true, addr: addr,
		closeCh: make(chan struct{})}
	pp := NewPeerPool([]string{addr, second}, true, 0, "")
	b.SetPeerPool(pp)
	go b.Run()
	t.Cleanup(func() { b.Close() })

	// The pool must stop pointing at the first endpoint. Poll through current() (which takes the pool's
	// own lock) rather than reading the health map directly — the dial loop writes it concurrently.
	// Poll rather than sleep a fixed budget: the re-dial backoff is jittered, so the second attempt has
	// no fixed time.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pp.current() != addr {
			return // burnDest() ran: the endpoint was marked and the pool advanced
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pool never moved off %s after repeated handshake failures — a connect-then-drop endpoint is "+
		"never burned, so rotation is inert against payload-killing interference", addr)
}
