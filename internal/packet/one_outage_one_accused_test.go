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

// ...and the accusation has to survive the RECONNECT, which is where freezing only the dial target was
// not enough. Replayed from core13 with the frozen target already in place:
//
//	1787533929  fail 185.143.23.238   the pinned edge -- the freeze held
//	1787533931  fail 185.143.23.238   ...and here
//	1787533933  fail 172.67.214.138   the tunnel came back here a second ago, and the rungs were gone
//	1787533934  ok   104.21.42.53 carrying
//
// The last verdict is honest about the pair it names: nothing was crossing on it yet. What is not
// honest is spending a climb on one endpoint and landing it on another.
func TestAClimbDoesNotLandOnWhoeverCameBack(t *testing.T) {
	const dead, back, sni = "dead:443", "back:443", "front-a"
	b, p := edgeCarrier(t, []string{dead, back}, snis(sni))
	// The two rungs Run() wires. Without a budget every verdict walks, and there is no climb to
	// protect in the first place.
	b.rc.port.setRoll(func() bool { return true })
	b.rc.session.setDrop(func() bool { return true })

	// The outage runs on the edge that will not open, spending the rungs.
	b.pretendDown()
	b.noteAttempt(dead, sni)
	for i := 0; i < portTries+1; i++ {
		b.tunFailAsTheNodeWould(t)
	}
	if got := stateOf(p.healthRows(), "ip", dead); got != "healthy" {
		t.Fatalf("setup: the free rungs should not have condemned anything yet (%s is %q)", dead, got)
	}

	// Now it comes back somewhere else, and the very next sweep judges THAT.
	b.pretendConnected(back, sni)
	for i := 0; i < 2; i++ {
		b.tunFailAsTheNodeWould(t)
	}

	if got := stateOf(p.healthRows(), "ip", back); got != "healthy" {
		t.Errorf("the edge the tunnel had just come back on is %q; the climb was about %s", got, dead)
	}
	if got := stateOf(p.healthRows(), "sni", sni); got != "healthy" {
		t.Errorf("the domain is %q; the lap it rode in on belonged to the other edge's climb", got)
	}
}

// ...and it must cost the newcomer NOTHING. The first rung tears the carrier down to redraw its
// source port, so spending one on the verdict that noticed the move closes the connection that has
// just come up -- and the next verdict then finds nothing crossing for a reason we caused. Measured on
// core13 with that spend in place: connected at 435.858, torn down at 437.233, burned at 438.233.
func TestNoticingTheMoveCostsTheNewcomerNothing(t *testing.T) {
	const dead, back, sni = "dead:443", "back:443", "front-a"
	b, _ := edgeCarrier(t, []string{dead, back}, snis(sni))
	rolls := 0
	b.rc.port.setRoll(func() bool { rolls++; return true })
	b.rc.session.setDrop(func() bool { return true })

	b.pretendDown()
	b.noteAttempt(dead, sni)
	b.tunFailAsTheNodeWould(t)
	spent := rolls

	b.pretendConnected(back, sni)
	b.tunFailAsTheNodeWould(t)
	if rolls != spent {
		t.Errorf("the verdict that noticed the move spent a rung (%d -> %d). On tcp that rung is a "+
			"teardown, so it closes the connection that just came up", spent, rolls)
	}

	// ...and the climb resumes on the newcomer with the verdict after it.
	b.tunFailAsTheNodeWould(t)
	if rolls == spent {
		t.Errorf("the new climb never started: still %d rungs spent", rolls)
	}
}

// Every session gets its own epoch, even when it reconnects to exactly what it left.
//
// The epoch is the only thing keeping a verdict measured on one session from being charged to the
// next: the node stamps it before the probe, re-reads it after, and the core drops a verdict whose
// epoch has moved. On an http or grpc carrier the published path has NO local half -- src "" and
// sport 0 -- so a reconnect to the same edge under the same domain produced a byte-identical path and
// the epoch stood still. Measured on core13, at 50 ms resolution:
//
//	t+00.051  epoch=1  pair=185  ready=false    the outage opens on the pinned edge
//	t+11.618  epoch=1  pair=104  ready=true     back on the good edge -- SAME epoch
//	t+12.022  verdict: fail 104                 the probe had run while it was down
//	t+12.073  104 burned
func TestEverySessionGetsItsOwnEpoch(t *testing.T) {
	b, _ := edgeCarrier(t, []string{"ip1:443"}, snis("front-a"))
	// What an http carrier's path looks like: no local address at all.
	live := pathKey{Dst: "ip1", Dport: 443, SNI: "front-a"}
	up := false
	b.st.tracker.setLive(func() (pathKey, bool) {
		if !up {
			return pathKey{}, false
		}
		return live, true
	})

	up = true
	b.st.newSession()
	b.st.write()
	first := b.st.pathEpoch()
	if first == 0 {
		t.Fatal("setup: the first session never took an epoch")
	}

	up = false // the carrier drops; the path goes empty, which observe ignores
	b.st.write()
	up = true // ...and comes back on exactly the same edge and domain
	b.st.newSession()
	b.st.write()

	if got := b.st.pathEpoch(); got == first {
		t.Errorf("a whole session came and went and the epoch is still %d. Every verdict measured "+
			"on the session before it now looks current", got)
	}
}

// The judge is one piece of code for every carrier, so the direct pools inherit the same rule -- and
// the same exposure, which was measured on core11 (raw): four verdicts naming one destination and a
// fifth naming the one the walk had just moved to, one second before it started carrying.
func TestAClimbDoesNotLandOnWhoeverCameBackOnADirectPool(t *testing.T) {
	const gone, back = "1.1.1.1:443", "2.2.2.2:443"
	b, pp, _ := peerCarrier(t, []string{gone, back}, nil)
	b.rc.port.setRoll(func() bool { return true })
	b.rc.session.setDrop(func() bool { return true })

	b.pretendConnected(gone, "")
	for i := 0; i < portTries+1; i++ {
		b.tunFailAsTheNodeWould(t)
	}
	if got := stateOf(pp.healthRows(), "dst", gone); got != "healthy" {
		t.Fatalf("setup: the free rungs should not have condemned anything yet (%s is %q)", gone, got)
	}

	b.pretendConnected(back, "")
	for i := 0; i < 2; i++ {
		b.tunFailAsTheNodeWould(t)
	}

	if got := stateOf(pp.healthRows(), "dst", back); got != "healthy" {
		t.Errorf("the destination the tunnel had just come back on is %q; the climb was about %s", got, gone)
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
