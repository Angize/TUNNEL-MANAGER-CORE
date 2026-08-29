package packet

import "testing"

// One path forward, the way a source-port draw is: a new tuple, one more epoch.
func advancePath(st *coreStatus, sport uint16) {
	st.tracker.observe(pathKey{Src: "94.182.131.47", Sport: sport, Dst: "91.107.169.159", Dport: 4500}, true)
}

// The verdict a recovery cannot deliver in time.
//
// A recovery moves the epoch while the probe that measures it is still running: the ladder draws a
// port, the handshake on it lands, and each of those is a step. The node reads the epoch BEFORE its
// sweep and stamps its verdict with it, so the "traffic is crossing" that proves the tunnel is back
// arrives naming the epoch the carrier has just left.
//
// The guard is symmetric in the source and asymmetric in effect. A FAIL is FOLLOWED by the epoch move
// it causes -- the ladder spends a rung on it -- so it always lands. An OK is STRADDLED by the move
// that proves it right, so it never does. Measured on the fleet 2026-08-28: the node wrote its OK at
// 20:51:51 and the core logged "dropping a tun-probe verdict for path epoch 39 - the carrier is on 40
// now" in the same second; eight verdicts died that way in one outage and not one was off by more than
// a single step. Nothing else calls success(), so the backoff climbed 45 -> 180 -> 600 across two
// reconnects without once being forgiven, the rungs were never handed back, and no line in the status
// ring ever said a port had been redrawn.
func TestAnOkOneEpochBehindStillForgivesTheBackoff(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	toDeadEnd(t, rc, rolls, drops, rot)
	if armedFor(rc) <= 0 {
		t.Fatalf("setup: a dead end must arm the revive clock, armed for %v", armedFor(rc))
	}
	spentRolls := *rolls

	advancePath(rc.st, 8302)
	measured := rc.st.pathEpoch()
	advancePath(rc.st, 2380)
	if rc.st.pathEpoch() != measured+1 {
		t.Fatalf("setup: want the carrier one step past the probe, measured %d and carrier %d",
			measured, rc.st.pathEpoch())
	}

	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, measured, poolCmd{Cmd: cmdOK, Low: low, High: high})
	rc.poll(noRot, rot, nil, rc.st.pathEpoch)

	if armedFor(rc) > 0 {
		t.Errorf("an OK one epoch behind left the backoff armed for %v -- the carrier moved BECAUSE "+
			"the path came back, so this is the only shape a measured recovery ever has", armedFor(rc))
	}
	// Forgiving the wait while leaving the ladder empty would still strand the next outage on
	// whatever port this one happened to end on, so the rungs have to come back with it.
	toDeadEnd(t, rc, rolls, drops, rot)
	if *rolls-spentRolls != portTries {
		t.Errorf("the ladder did not come back in full: %d draws after the OK, want %d",
			*rolls-spentRolls, portTries)
	}
}

// The mutation control for the test above. A FAIL still CHARGES an endpoint, so it must still be about
// the path the carrier is on -- otherwise the burn lands on whoever happens to be up, which is the
// whole reason the guard exists. Dropping the guard outright would pass the test above and fail this
// one.
func TestAFailOneEpochBehindStillChangesNothing(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	toDeadEnd(t, rc, rolls, drops, rot)
	armed, spentRolls, spentDrops := armedFor(rc), *rolls, *drops

	advancePath(rc.st, 8302)
	measured := rc.st.pathEpoch()
	advancePath(rc.st, 2380)

	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, measured, poolCmd{Cmd: cmdFail, Low: low, High: high})
	rc.poll(noRot, rot, nil, rc.st.pathEpoch)

	if *rolls != spentRolls || *drops != spentDrops {
		t.Errorf("a stale FAIL spent a rung: %d draws / %d handshakes, want %d / %d",
			*rolls, *drops, spentRolls, spentDrops)
	}
	if armedFor(rc) != armed {
		t.Errorf("a stale FAIL moved the revive clock: armed for %v, want %v", armedFor(rc), armed)
	}
}
