package packet

import (
	"testing"
)

func TestTheCursorCannotOutrunTheEpoch(t *testing.T) {
	cli, _, a1, a2, _, _ := probePair(t, "epoch")
	p := cli.pp

	settledEpoch(t, cli.st)

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
			continue
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
