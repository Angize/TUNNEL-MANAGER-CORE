//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
)

// Where the pool says it is pointing, as the node reads it out of the one status file.
func destPoolActive(t *testing.T, b *TCP) string {
	t.Helper()
	return b.readStatus(t).Pair.Low
}

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
			c.Close()
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
	b := &TCP{cryptoOn: true, cipher: "aes-256-gcm", psk: "warm-dst-cursor-psk-abcdefghijk",
		idle: connIdle, ping: pingEvery, isClient: true, addr: addr,
		stTag: "tcp", closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(dir, "core.status"))
	b.warmNext = make(chan *warmDial, 1)
	b.SetPeerPool(NewPeerPool([]string{addr, second, third}, 0))

	live := b.pp.current()
	if got := destPoolActive(t, b); got != live {
		t.Fatalf("the pool starts describing %q, not %q — the rest of this test would be vacuous", got, live)
	}

	if _, moved := b.pp.rotateOnce(); !moved {
		t.Fatal("rotateOnce did not move in a 3-endpoint pool")
	}
	// buildWarm no longer knows which pool it dialled for, so the cursor restore is the CALLER's, and the
	// dial loop does exactly this pair. Driving only half of it would prove nothing about either.
	if b.buildWarm(b.sourceIP(), true) {
		t.Fatal("buildWarm reported success against an endpoint that closes before a single core frame")
	}
	b.pp.keepCursorOn(live)
	if w := b.takeWarm(); w != nil {
		w.conn.Close()
		t.Fatal("a failed warm build parked a carrier")
	}
	if got := destPoolActive(t, b); got != live {
		t.Errorf("after a failed warm build the pool calls %s active, but the tunnel never left %s — the panel marks the wrong IP live, and the next beat rotates onto the endpoint it is already on", got, live)
	}

	if got := burnedIn(b.pp); len(got) > 0 {
		t.Errorf("a failed warm build condemned %v. The dial that could not come up is the SAME evidence "+
			"a dial failure gives, and only the node's tun probe burns on it — a proactive build that "+
			"loses a race must cost nothing", got)
	}
}
