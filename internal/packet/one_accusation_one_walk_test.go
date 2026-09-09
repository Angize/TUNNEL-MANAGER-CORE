package packet

import "testing"

// The 2026-09-08 core13 outage, as the panel showed it: "CDN edge rotation -> 104.21.42.53" three times
// in eleven seconds, every line naming the same destination, and the pool never went anywhere new. A
// scheduled rotation had put the ws pool on an edge that refuses every connection. The ladder walked off
// it once, correctly -- and then judge, which reads the pair the CARRIER last exercised, saw that same
// dead edge again, dragged the cursor back onto it with keepCursorOn and walked off it a second and a
// third time. The dial in between read the rewound cursor and returned to the dead edge, which is why
// the tunnel was down for twenty seconds instead of two, and the third phantom step completed an
// odometer lap that burned cdn.spacefly.ir -- a domain the probe had never accused.
//
// livePairNow reports the last ATTEMPTED pair while the carrier is down, and a carrier asleep in its
// reconnect backoff attempts nothing, so nothing refreshes it. Modelled here by not calling noteAttempt
// again: the node goes on naming the pair the status file still shows.
func TestOneAccusationBuysOneWalk(t *testing.T) {
	const dead, sni = "dead:443", "front-a"
	b, pp, sp := edgeCarrier(t, []string{dead, "good:443", "spare:443"}, snis(sni))
	b.rc.port.setRoll(func() bool { return true })

	b.pretendDown()
	b.noteAttempt(dead, sni)

	left := false
	for i := 0; i < 4*(portTries+2); i++ {
		b.tunFail(t, dead, sni)
		switch cur := pp.current(); {
		case cur != dead:
			left = true
		case left:
			t.Fatalf("verdict %d put the cursor back on %s after the ladder had already walked off it; "+
				"the next dial goes to the dead edge again", i, dead)
		}
	}

	rotations := 0
	for _, e := range b.readStatus(t).Events {
		if e.Kind == "down" && e.Code == "edge-rotate" {
			rotations++
		}
	}
	if rotations != 1 {
		t.Errorf("%d edge-rotate events for one accused pair; the ladder may step off %s once, and then "+
			"it waits for the carrier to reach somewhere new", rotations, dead)
	}
	if got := stateOf(sp.healthRows(), "sni", sni); got != "healthy" {
		t.Errorf("the domain is %q; only phantom steps could have driven the odometer far enough to lap "+
			"on a three-edge pool", got)
	}
}

// The guard has to be a pause, not a lock. The first attempt at this fix latched on the accusation
// itself, and TestNoVerdictEverCondemnsAnEndpointTheTunnelWasNotOn caught what that costs: an operator
// jumping back onto an endpoint the ladder had walked off left the ladder unable to charge anything
// ever again. Keying on the endpoint's own condemnation instead means the jump clears it -- selectEntry
// forgives the entry it lands on -- and so does its retest window coming round.
func TestTheGuardLiftsWhenTheEndpointIsForgiven(t *testing.T) {
	const dead, sni = "dead:443", "front-a"
	b, pp, _ := edgeCarrier(t, []string{dead, "good:443"}, snis(sni))
	b.rc.port.setRoll(func() bool { return true })

	b.pretendDown()
	b.noteAttempt(dead, sni)
	for i := 0; i < 2*(portTries+2); i++ {
		b.tunFail(t, dead, sni)
	}
	if got := stateOf(pp.healthRows(), "ip", dead); got == "healthy" {
		t.Fatalf("setup: %s should have been condemned by the first walk, it is %q", dead, got)
	}

	pp.selectEntry(dead)
	if got := stateOf(pp.healthRows(), "ip", dead); got != "healthy" {
		t.Fatalf("the operator jump did not forgive %s, it is %q", dead, got)
	}

	moved := false
	for i := 0; i < portTries+2 && !moved; i++ {
		moved = b.tunFail(t, dead, sni)
	}
	if !moved {
		t.Error("the ladder never moved again after the operator jumped back onto the endpoint it had " +
			"walked off; the guard is a lock, not a pause")
	}
}
