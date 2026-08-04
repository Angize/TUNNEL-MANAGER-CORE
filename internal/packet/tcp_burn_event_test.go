package packet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTCPTunProbeBurnNamesTheEndpointItBurned drives the node's failover command through the real
// cmd-file path a direct-tcp client polls, and asserts the event it publishes names the endpoint the
// node condemned. burnAdvance returns where the pool moved TO, so publishing that made the panel's
// system log blame the healthy replacement for the fault of the one it replaced — the datagram twin
// (pollPins) reads current() before the burn precisely to avoid this.
func TestTCPTunProbeBurnNamesTheEndpointItBurned(t *testing.T) {
	dir := t.TempDir()
	st := newCoreStatus(filepath.Join(dir, "core.json"), "tcp · lab", roleOf(true))
	p := NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, true, 0, filepath.Join(dir, "pool.json"))
	b := &TCP{pp: p, st: st, isClient: true, closeCh: make(chan struct{})}
	defer close(b.closeCh)

	gone := p.current()
	if err := os.WriteFile(p.cmdPath(), []byte(`{"cmd":"fail"}`), 0o644); err != nil {
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
	burned := p.health[gone] != nil
	p.mu.Unlock()
	if !burned {
		t.Fatalf("%s was named but never burned", gone)
	}
}
