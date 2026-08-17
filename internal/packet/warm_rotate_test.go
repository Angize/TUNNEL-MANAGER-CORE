//go:build linux

package packet

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBuildWarmFailurePublishesNoRotation pins the contract make-before-break rests on: a warm carrier
// that will not come up must BURN its endpoint and ANNOUNCE NOTHING. Announcing before the replacement
// exists leaves the panel showing an endpoint the tunnel is not on and arms a down() the next connect
// pairs as a phantom self-heal. The listener accepts and closes, so the HANDSHAKE fails, not the dial.
func TestBuildWarmFailurePublishesNoRotation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
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
	second := net.JoinHostPort("127.0.0.2", port) // loopback alias, same listener

	path := filepath.Join(t.TempDir(), "core-warm.status")
	active := "tcp · " + addr
	b := &TCP{cryptoOn: true, cipher: "aes-256-gcm", psk: "warm-rotate-psk-abcdefghijklmno",
		keepalive: time.Second, idle: deadWindow(time.Second), isClient: true, addr: addr,
		stTag: "tcp", closeCh: make(chan struct{})}
	b.st = newCoreStatus(path, active)
	b.warmNext = make(chan *warmDial, 1) // dialLoop's job; this test drives buildWarm directly
	b.SetPeerPool(NewPeerPool([]string{addr, second}, 0, ""))
	// Also wire a SOURCE pool and rotate it, for the source half: the proactive timer advances the source
	// (via rotateSourceTCP(true)) BEFORE buildWarm proves the move. The source-rotate event must NOT be
	// published until the warm carrier goes live — so a build that then fails announces nothing at all.
	// (The source IPs need not be local: dialer() skips an unbindable bind and dials from the default.)
	b.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, 0, ""))
	if _, moved := b.rotateSourceTCP(true); !moved {
		t.Fatal("proactive source rotate should move in a 2-entry pool")
	}

	burns := 0
	if b.buildWarm(func() { burns++ }, b.sourceIP(), true, "") {
		t.Fatal("buildWarm reported success against an endpoint that closes before a single core frame")
	}
	if burns != 1 {
		t.Fatalf("a warm build that fails its handshake must burn the endpoint exactly once, got %d", burns)
	}
	if w := b.takeWarm(); w != nil {
		w.conn.Close()
		t.Fatal("a failed warm build parked a carrier — dialLoop would later adopt it as if it were fresh")
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var doc struct {
		Active string `json:"active"`
		Events []struct {
			Kind string `json:"kind"`
			Code string `json:"code"`
		} `json:"events"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if doc.Active != active {
		t.Errorf("active moved to %q on a rotation that never happened; the tunnel is still on %q", doc.Active, active)
	}
	for _, e := range doc.Events {
		t.Errorf("a failed warm build wrote event %q/%q; it must publish nothing — the carrier never moved", e.Kind, e.Code)
	}
}
