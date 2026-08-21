package packet

import (
	"path/filepath"
	"testing"
)

// The bug this closes, from core13 on 2026-08-21: the operator pinned an edge they knew was blocked.
// The carrier came down to obey, the dial to the pinned edge timed out, and while the tunnel had no
// carrier at all the status file still published a pair -- the pool CURSOR, resting on the edge the
// tunnel had been using before. The node's probe named that edge, and the ladder burned it. An edge
// that had done nothing wrong lost ten minutes, and the operator saw two burns for one bad edge.
func TestTheStatusNamesWhatIsBeingTriedNotTheCursor(t *testing.T) {
	const was, pinned, third = "10.0.0.1:443", "10.0.0.2:443", "10.0.0.3:443"
	p := newWSPool([]string{was, pinned, third}, snis("x"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

	// Before the first dial the cursor is a fair prediction: it is what that dial will use.
	if _, high := b.livePairNow(); high != was {
		t.Fatalf("before any dial the carrier names %q, want the cursor %q", high, was)
	}

	b.noteAttempt("x", pinned)
	low, high := b.livePairNow()
	if high != pinned {
		t.Fatalf("while dialling %s the carrier reports %q; a probe that measures this outage must name "+
			"the edge being TRIED, not one the pool merely points at", pinned, high)
	}
	if low != "x" {
		t.Fatalf("the domain half reads %q, want %q", low, "x")
	}

	// The pin is dropped and the pool walks on: the cursor is now somewhere else entirely. The last
	// attempt is still the honest answer until the next dial replaces it.
	p.markSuspect("ip", pinned, "dial")
	p.advance()
	if cur, _, _ := p.current(); cur == pinned {
		t.Fatal("setup: the pool did not move off the burned edge")
	}
	if _, high := b.livePairNow(); high != pinned {
		t.Fatalf("the pool moved to %q and the carrier followed it in the status; the cursor is where we "+
			"would go NEXT, not what the probe just measured", high)
	}
}

// The other half: a verdict that names nothing must not fall through to the walk. It reaches the core
// whenever the carrier is between dials -- and right after a relaunch, when the status file has not
// been written yet and epoch 0 matches epoch 0, so the stale guard lets it through.
func TestANamelessVerdictSpendsTheRungsAndBurnsNobody(t *testing.T) {
	dir := t.TempDir()
	pp := NewPeerPool([]string{"1.1.1.1", "2.2.2.2"}, 0)
	b := &TCP{isClient: true, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(dir, "core.status"))
	b.SetPeerPool(pp)
	b.rc.port.setRoll(func() bool { return true })

	for i := 1; i <= portTries+2; i++ {
		b.rc.judge(poolCmd{Cmd: cmdFail}, b.rotateLowTCP, b.rotateHighTCP, 0)
		pp.mu.Lock()
		burns := len(pp.health.recs)
		pp.mu.Unlock()
		if burns != 0 {
			t.Fatalf("verdict %d named no endpoint and %d were burned anyway — the burn lands on whatever "+
				"the cursor rests on, which nothing measured", i, burns)
		}
	}

	// ...and a verdict that DOES name the endpoint being tried still walks, so this guard cannot be
	// satisfied by refusing every fail.
	b.noteAttempt(pp.current(), "")
	low, high := b.rc.livePair()
	if low == "" {
		t.Fatal("setup: the carrier still names nothing after an attempt was recorded")
	}
	b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	pp.mu.Lock()
	named := len(pp.health.recs)
	pp.mu.Unlock()
	if named == 0 {
		t.Fatal("a verdict that named the live destination burned nothing — the free rungs were already " +
			"spent, so the ladder has stalled")
	}
}
