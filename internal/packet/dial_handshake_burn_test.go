//go:build linux

package packet

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDialFailureLeavesTheDirectPoolAlone(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
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
	second := net.JoinHostPort("127.0.0.2", port)

	dev, _ := tunPair(t, "hsburn")
	dir := t.TempDir()
	b := &TCP{dev: dev, cryptoOn: true, cipher: "aes-256-gcm", psk: "handshake-burn-psk-abcdefghijkl",
		keepalive: time.Second, idle: deadWindow(time.Second), isClient: true, addr: addr,
		st: newCoreStatus(filepath.Join(dir, "core.json"), "tcp · hsburn"), closeCh: make(chan struct{})}
	pp := NewPeerPool([]string{addr, second}, 0, filepath.Join(dir, "pool.json"))
	b.SetPeerPool(pp)
	go b.Run()
	t.Cleanup(func() { b.Close() })

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

	if werr := os.WriteFile(b.st.verdictPath(), []byte(`{"cmd":"fail","key":"`+addr+`"}`), 0o644); werr != nil {
		t.Fatalf("write cmd: %v", werr)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if pp.current() != addr {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the node's fail command never moved the pool off %s", addr)
}
