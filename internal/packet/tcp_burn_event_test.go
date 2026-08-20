package packet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTCPTunProbeBurnNamesTheEndpointItBurned(t *testing.T) {
	dir := t.TempDir()
	st := newCoreStatus(filepath.Join(dir, "core.json"), "tcp · lab")
	p := NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0, filepath.Join(dir, "pool.json"))
	b := &TCP{pp: p, st: st, isClient: true, closeCh: make(chan struct{})}
	defer close(b.closeCh)
	armAndSpendTheFreeRungs(t, b)

	gone := p.current()
	if err := os.WriteFile(st.verdictPath(), []byte(`{"cmd":"fail","key":"`+gone+`"}`), 0o644); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
	go b.peerPinPollLoop()

	var burn coreEvent
	deadline := time.Now().Add(10 * time.Second)
	for burn.Code == "" {
		st.mu.Lock()
		for _, e := range st.events {
			if e.Kind == "burn" && e.Code == "tun-probe" {
				burn = e
			}
		}
		st.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the node's fail command produced no burn event")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if burn.Detail != "ip:"+gone {
		t.Fatalf("the burn event names %s, but the node condemned %s", burn.Detail, gone)
	}
	p.mu.Lock()
	burned := p.health.recs[gone] != nil
	p.mu.Unlock()
	if !burned {
		t.Fatalf("%s was named but never burned", gone)
	}
}
