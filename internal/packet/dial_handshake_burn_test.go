//go:build linux

package packet

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDialFailureLeavesTheDirectPoolAlone pins the one-judge rule on the carrier that used to have an
// opinion of its own. A DPI that lets the TCP handshake complete and then kills the payload looks
// exactly like this listener — accept, then close — and tcp used to burn the endpoint for it. It must
// not: a dial that failed says the carrier could not come up, not which IP is to blame, and the node's
// tun probe is the only thing positioned to answer that. The same test then shows the node's verdict
// moving the pool, so "nothing burns it" is not mistaken for "nothing can".
func TestDialFailureLeavesTheDirectPoolAlone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { // accept, then drop before a single core frame is exchanged
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
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
	pp := NewPeerPool([]string{addr, second}, true, 0, filepath.Join(t.TempDir(), "pool.json"))
	b.SetPeerPool(pp)
	go b.Run()
	t.Cleanup(func() { b.Close() })

	// Give the dial loop several failed attempts. The pool must not move and nothing may be burned.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if pp.current() != addr {
			t.Fatalf("a failed handshake moved the pool to %s — only the node's tun probe may", pp.current())
		}
		pp.mu.Lock()
		n := len(pp.health.recs)
		pp.mu.Unlock()
		if n != 0 {
			t.Fatalf("a failed handshake burned %d endpoint(s) — only the node's tun probe may", n)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The node's verdict, through the file the core really polls, DOES move it.
	if werr := os.WriteFile(pp.cmdPath(), []byte(`{"cmd":"fail","key":"`+addr+`"}`), 0o644); werr != nil {
		t.Fatalf("write cmd: %v", werr)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pp.current() != addr {
			return // burned and advanced on the node's word
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the node's fail command never moved the pool off %s", addr)
}
