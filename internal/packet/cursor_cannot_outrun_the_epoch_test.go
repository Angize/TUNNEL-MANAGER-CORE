package packet

import (
	"testing"
	"time"
)

// TestTheCursorCannotOutrunTheEpoch is the invariant the verdict path rests on, so it is proved on a
// REAL carrier rather than assumed.
//
// judge() no longer compares the verdict's key against anything: it acts on the endpoint the node
// named. That is only sound if the pool's cursor cannot move without the epoch moving too — because
// the epoch is what drops a verdict measured on a path the tunnel has left. On the datagram carriers
// the cursor and the live destination move in the same call, and that call publishes, so the epoch
// steps before the poller can read it.
//
// Driven through rotatePeerUDP, not through the pool, precisely because the pool alone would prove
// nothing: moving the cursor without the carrier is a state the product cannot be in, and a test that
// arranged it would be describing a different program.
//
// It is a PREMISE, not a regression guard: it passes either side of the change that made judge() stop
// asking, and it is here so that a future edit which lets the cursor lead the carrier fails loudly
// instead of quietly reopening the mis-target.
func TestTheCursorCannotOutrunTheEpoch(t *testing.T) {
	cli, _, a1, a2, _, _ := probePair(t, time.Second, "epoch")
	p := cli.pp

	settledEpoch(t, cli.st) // wait until a path with a session on it is published

	for round, proactive := range []bool{true, false, true, false} {
		p.mu.Lock()
		curBefore := p.addrs[p.cur]
		p.mu.Unlock()
		epochBefore := cli.st.pathEpoch()

		cli.rotatePeerUDP(proactive)

		p.mu.Lock()
		curAfter := p.addrs[p.cur]
		p.mu.Unlock()
		epochAfter := cli.st.pathEpoch()

		if curAfter == curBefore {
			continue // the pool declined to move (everything else burned) — nothing to check
		}
		if epochAfter == epochBefore {
			t.Fatalf("round %d (proactive=%v): the cursor moved %s -> %s and the epoch stood still at %d. "+
				"A verdict measured on %s would then be accepted as current and charged to %s",
				round+1, proactive, curBefore, curAfter, epochAfter, curBefore, curAfter)
		}
		if live := cli.peer.Load(); live == nil || live.String() != curAfter {
			t.Fatalf("round %d: the pool says %s, the carrier is sending to %v — the cursor is supposed to "+
				"BE the live destination on this carrier", round+1, curAfter, live)
		}
	}
	if a1 == a2 {
		t.Fatal("the harness handed out one endpoint twice; the rotation could not have moved")
	}
}
