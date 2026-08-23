package packet

import "testing"

// The node does not invent the pair it blames: it reads it out of the status file the core publishes,
// every sweep, and stamps the epoch from that same read. A test that passes fixed names cannot see the
// name change under it, which is exactly what happened in production.
func (b *TCP) tunFailAsTheNodeWould(t *testing.T) bool {
	t.Helper()
	st := b.readStatus(t)
	return b.deliver(t, poolCmd{Cmd: cmdFail, Low: st.Pair.Low, High: st.Pair.High, Epoch: st.Epoch},
		b.st.verdictPath())
}

// Pinning an edge that refuses the dial must not cost a healthy one.
//
// Measured on core13: the operator pinned a dead edge, the dial was refused, the pin released, and the
// retry resolved to the healthy edge the tunnel had been on. The node's next sweep read THAT name out
// of the status file, the ladder's rungs had already been spent by the two verdicts before it, and the
// burn landed on the healthy edge -- which had not carried a byte during the whole outage.
//
//	1787459059  fail 185.143.23.238   the pinned edge, refused
//	1787459061  fail 185.143.23.238
//	1787459063  fail 104.21.42.53     the same outage, renamed
//	1787459063  burn ip:104.21.42.53
//
// Nothing else can rename the accused without going through a reconnect, and a reconnect bumps the
// path epoch, which the node's own staleness guard catches. This one moved with the epoch unchanged.
func TestPinningARefusingEdgeDoesNotBurnAHealthyOne(t *testing.T) {
	const good, sni = "good:443", "front-a"
	dead := freeTCPPort(t) // nothing listens there, so the dial is refused
	b, p := edgeCarrier(t, []string{good, dead}, snis(sni))

	b.pretendConnected(good, sni)
	if !b.operatorPin(t, "ip", dead) {
		t.Fatal("setup: the pin was not applied")
	}

	// What the carrier does next, in order: drop the session for the jump, try the pinned edge, get
	// refused, release the pin, and retry -- which now resolves to the healthy edge.
	b.pretendDown()
	b.noteAttempt(dead, sni)
	b.pinFailedOn(dead)
	b.noteAttempt(good, sni)

	if low, _ := b.livePairNow(); low != dead {
		t.Fatalf("the outage is published as %q; it opened on the pinned edge %q and no reconnect has "+
			"happened since, so nothing may have renamed it", low, dead)
	}

	// Now the node judges it, sweep after sweep, reading the name from the file each time.
	for i := 0; i < portTries+3; i++ {
		b.tunFailAsTheNodeWould(t)
	}

	if got := stateOf(p.healthRows(), "ip", good); got != "healthy" {
		t.Errorf("the healthy edge is %q. It carried the tunnel until the operator jumped off it and "+
			"never carried a byte during the outage that followed", got)
	}
	if got := stateOf(p.healthRows(), "ip", dead); got == "healthy" {
		t.Errorf("the edge that refused every dial for the whole outage is still %q", got)
	}
}

// And the same rule one level down: the walk must condemn the pair the verdict was ABOUT, not whatever
// the carrier reports by the time the arm runs. The dial loop connects on another goroutine, and the
// likeliest moment for it to succeed is the end of the outage the walk is answering.
func TestTheWalkCondemnsWhatTheVerdictMeasured(t *testing.T) {
	const sni = "front-a"
	b, p := edgeCarrier(t, []string{"ip1:443", "ip2:443"}, snis(sni))
	b.pretendConnected("ip1:443", sni)

	for i := 0; i < portTries+1; i++ {
		b.tunFail(t, "ip1:443", sni)
	}
	// The carrier lands on the other edge just as the walk is about to run its arm.
	b.rc.measured.Store(&pairNow{low: "ip1:443", high: sni})
	b.pretendConnected("ip2:443", sni)
	b.rotateLowTCP(false)

	if got := stateOf(p.healthRows(), "ip", "ip2:443"); got != "healthy" {
		t.Errorf("the edge the carrier had just connected on is %q; the verdict was about ip1", got)
	}
	if got := stateOf(p.healthRows(), "ip", "ip1:443"); got == "healthy" {
		t.Errorf("the edge the verdict measured is still %q", got)
	}
}
