package packet

import (
	"testing"
)

// A pool of one has nowhere to rotate to and currentLocked keeps serving its only entry from the
// fallback, so the burn changes no behaviour. It is recorded anyway: a green row under a dead tunnel
// tells the operator that endpoint is fine, and these rows are what they read to decide what to
// replace. The record is also self-healing -- the tun probe's ok clears it the moment traffic crosses.
func TestALoneDestinationIsStillCondemned(t *testing.T) {
	dst := NewPeerPool([]string{"only"}, 0)
	b := &TCP{isClient: true}
	b.SetPeerPool(dst)
	for i := 0; i < 5; i++ {
		tcpWalk(b)
	}
	if got := burnedIn(dst); len(got) == 0 {
		t.Fatal("the only destination stayed green through five verdicts. Nothing rotates away from " +
			"it, but the panel then shows a healthy endpoint on a tunnel that is carrying nothing")
	}

	// ...and it is still only ONE burn, however long the outage runs: healthSet.burn is a no-op while
	// the backoff it already stamped has not elapsed, so the operator gets one line, not one per sweep.
	dst.mu.Lock()
	fails := dst.health.recs["only"].fails
	dst.mu.Unlock()
	if fails != 0 {
		t.Fatalf("the ladder deepened a burn nothing re-measured: fails=%d", fails)
	}
}
