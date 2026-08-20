//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
)

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
			c.Close()
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
		idle: connIdle, ping: pingEvery, isClient: true, addr: addr,
		stTag: "tcp", closeCh: make(chan struct{})}
	b.st = newCoreStatus(path, active)
	b.warmNext = make(chan *warmDial, 1)
	dests := []string{addr, second}
	b.SetPeerPool(NewPeerPool(dests, 0, ""))

	sp := NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, 0, srcPath)
	b.SetSourcePool(sp)

	for range dests {
		if b.buildWarm(b.sourceIP(), true) {
			t.Fatal("buildWarm reported success against an endpoint that closes before a single core frame")
		}
		if w := b.takeWarm(); w != nil {
			w.conn.Close()
			t.Fatal("a failed warm build parked a carrier")
		}
	}

	if burned := burnedIn(sp); len(burned) > 0 {
		t.Errorf("a failed warm build burned source(s) %v — the build died on the DESTINATION (which is burned separately) and nothing proved a source bad", burned)
	}
	for _, e := range coreStatusEvents(t, path) {
		t.Errorf("a failed warm build published %q/%q — the tunnel never left its source or its endpoint", e.Kind, e.Code)
	}

	b.rc.od.rot, b.rc.od.want = len(dests)-1, len(dests)
	if !tcpWalk(b) {
		t.Fatal("a failover burn did not take")
	}
	if burned := burnedIn(sp); len(burned) == 0 {
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
