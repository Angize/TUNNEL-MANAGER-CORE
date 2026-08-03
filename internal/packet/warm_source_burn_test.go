//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A failed make-before-break build must ANNOUNCE NOTHING and BURN NO SOURCE. burnAdvance walks the source
// once the destination pool has cycled, and its failover form publishes a rotation the live carrier never
// made. A stray burn lands on the CANDIDATE source, not the live one, since the timer has already
// advanced cur. This drives the REAL callback buildWarm receives; the sibling test passes a stub.
func TestFailedWarmBuildDoesNotBurnOrAnnounceTheLiveSource(t *testing.T) {
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

	dir := t.TempDir()
	path := filepath.Join(dir, "core-warm.status")
	srcPath := filepath.Join(dir, "src-pool.json")
	active := "tcp · " + addr
	b := &TCP{cryptoOn: true, cipher: "aes-256-gcm", psk: "warm-src-burn-psk-abcdefghijklmn",
		keepalive: time.Second, idle: idleFor(time.Second), isClient: true, addr: addr,
		stTag: "tcp", closeCh: make(chan struct{})}
	b.st = newCoreStatus(path, active, "client")
	b.warmNext = make(chan *warmDial, 1) // dialLoop's job; this test drives buildWarm directly
	b.SetPeerPool(NewPeerPool([]string{addr, second}, true, 0, ""))
	// Both source IPs are real loopback addresses, so neither is dropped for being unbindable — the
	// only thing that can burn one here is burnAdvance.
	sp := NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, true, 0, srcPath)
	b.SetSourcePool(sp)

	// One warm build per destination endpoint, so the pool cycles and burnAdvance reaches the source
	// walk — the branch under test. Every one of them fails: the live carrier never moves.
	for i := 0; i < b.pp.size(); i++ {
		if b.buildWarm(func() { b.burnAdvance(false) }, b.sourceIP(), true, "") {
			t.Fatal("buildWarm reported success against an endpoint that closes before a single core frame")
		}
		if w := b.takeWarm(); w != nil {
			w.conn.Close()
			t.Fatal("a failed warm build parked a carrier")
		}
	}

	// Advancing the source is fine and is what the proactive form does — the move becomes real at the
	// adoption site when a warm carrier finally goes live. Burning one is not: nothing here proved a
	// source bad, and a burned entry is one rotation will avoid.
	if burned := poolBurned(sp); len(burned) > 0 {
		t.Errorf("a failed warm build burned source(s) %v — the build died on the DESTINATION (which is burned separately) and nothing proved a source bad", burned)
	}
	for _, e := range coreStatusEvents(t, path) {
		t.Errorf("a failed warm build published %q/%q — the tunnel never left its source or its endpoint", e.Kind, e.Code)
	}

	// ...and the other half of the contract: a REAL failover still burns and still announces, so this
	// fix cannot be satisfied by silencing the source walk everywhere.
	b.destRot.Store(int64(b.pp.size()) - 1) // one more burn cycles the pool
	if _, burned := b.burnAdvance(true); !burned {
		t.Fatal("a failover burn did not take")
	}
	if burned := poolBurned(sp); len(burned) == 0 {
		t.Error("a genuine failover burned no source: with every destination tried against it, walking off that source is the whole point")
	}
	found := false
	for _, e := range coreStatusEvents(t, path) {
		if e.Kind == "down" && e.Code == "src-rotate" {
			found = true
		}
	}
	if !found {
		t.Error("a genuine failover source rotation published no src-rotate event")
	}
}

// poolBurned lists every entry carrying a burn/suspect record.
func poolBurned(p *PeerPool) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, a := range p.addrs {
		if p.health[a] != nil {
			out = append(out, a)
		}
	}
	return out
}
