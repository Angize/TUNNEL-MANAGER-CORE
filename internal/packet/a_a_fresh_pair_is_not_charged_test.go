package packet

import "testing"

// Measured in production on a ws tunnel with three CDN edges: 185 was genuinely dead, the ladder burned
// it and arrived on 104, and 104 -- which nothing had faulted -- was burned six seconds later. The first
// verdict about 104 spent a rung, that rung closed the connection which had come up two seconds earlier,
// and the verdict after it measured the gap the core had just made.
//
// The rung that tears a carrier down may not be spent on a pair the ladder has only just arrived on.
func TestTheFirstVerdictAboutThePairTheWalkArrivedOnSpendsNothing(t *testing.T) {
	dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0)
	rc, rolls, drops := ladderOn(t, dst, nil)
	rot := func(bool) { dst.fail("tun-probe") }

	start, _ := rc.livePair()
	for i := 0; i < 40 && func() bool { now, _ := rc.livePair(); return now == start }(); i++ {
		failLivePair(t, rc, rot, noRot)
	}
	arrived, _ := rc.livePair()
	if arrived == start {
		t.Fatalf("setup: the ladder never walked off %s", start)
	}

	r0, d0 := *rolls, *drops
	failLivePair(t, rc, rot, noRot)
	if *rolls != r0 || *drops != d0 {
		t.Errorf("the first verdict about %s spent a rung (%d draws / %d handshakes -> %d / %d): that "+
			"rung tears down the connection which has just come up, and the verdict after it then "+
			"measures the gap we made", arrived, r0, d0, *rolls, *drops)
	}

	failLivePair(t, rc, rot, noRot)
	if *rolls == r0 && *drops == d0 {
		t.Errorf("two verdicts about %s and not one rung spent -- the climb has to START on the second "+
			"verdict, not never", arrived)
	}
}

// The pause is one verdict, for a pair the walk arrived on. The FIRST verdict of an outage still spends:
// there the carrier is already down, so there is nothing fresh to tear down and waiting only delays the
// recovery.
func TestTheFirstVerdictOfAnOutageStillSpendsARung(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)

	failLivePair(t, rc, noRot, func(bool) { src.nextEndpoint(false) })
	if *rolls+*drops != 1 {
		t.Errorf("the opening verdict of an outage spent %d rungs, want exactly 1 -- the ladder must "+
			"start climbing at once when nothing has just arrived", *rolls+*drops)
	}
}
