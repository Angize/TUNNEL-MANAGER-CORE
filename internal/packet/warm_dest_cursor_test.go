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

// destPoolActive reads the Active endpoint out of a PeerPool's own status file — the field the panel
// draws the "this one is live" marker from (`act = (d.active === ip)`).
func destPoolActive(t *testing.T, path string) string {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pool status %s: %v", path, err)
	}
	var doc struct {
		Active string `json:"active"`
	}
	if json.Unmarshal(buf, &doc) != nil {
		t.Fatalf("parse pool status %s", path)
	}
	return doc.Active
}

// A failed make-before-break build must leave the pool describing the endpoint the tunnel is on. The
// timer advances the pool, buildWarm dials what it advanced onto, and when that build fails the live
// connection deliberately STAYS — while fail() burns the candidate (right), advances the cursor again
// (fine) and publishes Active as wherever it now points (wrong). The source half was fixed first.
func TestFailedWarmBuildLeavesTheDestinationCursorWhereTheTunnelIs(t *testing.T) {
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
			c.Close() // TCP connects, the core handshake dies: buildWarm fails
		}
	}()

	addr := ln.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	second := net.JoinHostPort("127.0.0.2", port)
	third := net.JoinHostPort("127.0.0.3", port)

	dir := t.TempDir()
	poolPath := filepath.Join(dir, "dest-pool.json")
	b := &TCP{cryptoOn: true, cipher: "aes-256-gcm", psk: "warm-dst-cursor-psk-abcdefghijk",
		keepalive: time.Second, idle: idleFor(time.Second), isClient: true, addr: addr,
		stTag: "tcp", closeCh: make(chan struct{})}
	b.st = newCoreStatus(filepath.Join(dir, "core.status"), "tcp · "+addr)
	b.warmNext = make(chan *warmDial, 1)
	b.SetPeerPool(NewPeerPool([]string{addr, second, third}, true, 0, poolPath))

	live := b.pp.current() // where the (imaginary) live connection is
	if got := destPoolActive(t, poolPath); got != live {
		t.Fatalf("the pool starts describing %q, not %q — the rest of this test would be vacuous", got, live)
	}

	// Exactly what the rotation timer does: advance, try to build on the new endpoint, fail.
	if _, moved := b.pp.rotateOnce(); !moved {
		t.Fatal("rotateOnce did not move in a 3-endpoint pool")
	}
	if b.buildWarm(func() { b.burnAdvance(false) }, b.sourceIP(), true, live) {
		t.Fatal("buildWarm reported success against an endpoint that closes before a single core frame")
	}
	if w := b.takeWarm(); w != nil {
		w.conn.Close()
		t.Fatal("a failed warm build parked a carrier")
	}
	if got := destPoolActive(t, poolPath); got != live {
		t.Errorf("after a failed warm build the pool calls %s active, but the tunnel never left %s — the panel marks the wrong IP live, and the next beat rotates onto the endpoint it is already on", got, live)
	}
	// The burn must SURVIVE: that endpoint really did refuse to come up, and the next beat has to skip it.
	if len(poolBurned(b.pp)) == 0 {
		t.Error("the endpoint that would not come up was left healthy — the next beat walks straight back onto it")
	}
}
