package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func statusActive(t *testing.T, path string) string {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Active string `json:"active"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return doc.Active
}

// A carrier that cannot get a session up ANYWHERE never calls setActive again, so the last-connected
// string freezes. Everything downstream reads it: the node names that edge in its verdict, the core
// matches its own frozen copy, and the ladder runs against an edge it walked off hours ago -- while the
// edge that is actually failing is never blamed and stays green in the panel. Measured on core48.
func TestTheEdgePoolSaysWhereItIsGoingNotWhereItLanded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.status")
	p := newWSPool([]string{"e1", "e2"}, snis("x"), path)

	p.setActive(activeLabel("e1", "x")) // it connected on e1, once
	p.markSuspect("ip", "e1", "tun-probe")
	p.advanceIP() // the judge burned it and the walk moved off

	p.mu.Lock()
	landed := p.active
	p.mu.Unlock()
	if landed != activeLabel("e1", "x") {
		t.Fatalf("setup: the last-connected string is %q, so this test would prove nothing", landed)
	}

	ip, sni := p.activeCombo()
	if ip != "e2" || sni != "x" {
		t.Fatalf("activeCombo() = %s/%s, want e2/x. The verdict is keyed on this: naming the edge it "+
			"LANDED on sends every fail to an edge the pool already left", ip, sni)
	}
	if got := statusActive(t, path); got != activeLabel("e2", "x") {
		t.Fatalf("the status file publishes %q, want %q -- the node reads this to key its verdict, and "+
			"the panel reads it to draw which edge is live", got, activeLabel("e2", "x"))
	}
}

// The commitment the walk makes must survive the status writer, which now resolves the combo once a
// second and would otherwise step the cursor out from under a try in progress.
func TestPublishingTheCurrentComboDoesNotBreakTheWalksCommitment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ws.status")
	p := newWSPool([]string{"e1", "e2"}, snis("x", "y"), path)
	if !p.advance() {
		t.Fatal("setup: a 2x2 pool would not step")
	}
	ip, sni, _ := p.current()
	for i := 0; i < 5; i++ {
		p.writeStatus()
		got, gotSNI, _ := p.current()
		if got != ip || gotSNI.host != sni.host {
			t.Fatalf("write %d moved the live combo from %s/%s to %s/%s -- the walk deliberately stepped "+
				"onto one and the status writer must not re-select past it", i+1, ip, sni.host, got, gotSNI.host)
		}
	}
}
