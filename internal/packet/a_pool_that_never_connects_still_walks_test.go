package packet

import "testing"

// Every pool test in this package reaches its endpoints through pretendConnected, which is the one
// thing a blocked pool never gets to do. Measured on this tree before the fix: a three-endpoint pool
// whose dials are all refused reached its SECOND endpoint and never its third, in sixty verdicts.
//
//	edges reached in 60 verdicts: map[e2:true]
//	peers reached in 60 verdicts: map[d2:443:true]
//
// noteAttempt is one-shot (b.attempted), and the only thing that cleared the latch was b.serve()
// returning -- which needs a connection to have been established first. A pure dial-failure loop
// continues past that line forever, so tryPair stayed frozen on the first target. livePairNow falls
// back to tryPair whenever the carrier is down, so the status file kept naming that one endpoint, the
// node's verdict named it back, judge dragged the cursor onto it with keepCursorOn, and the walk
// stepped exactly one. The reachable set was a single endpoint, whatever the pool held.
//
// A carrier that never connects is not a corner case: it is what a CDN pool looks like the moment the
// censor blocks the edges it is holding, which is the whole reason the pool exists.
//
// dialLoop, modelled honestly: every attempt dials whatever the pool now points at and records it, as
// dialCarrier and dialDirect both do.
func TestAPoolThatNeverConnectsStillWalksToItsLastEndpoint(t *testing.T) {
	t.Run("edge pool", func(t *testing.T) {
		b, p := edgeCarrier(t, []string{"e1", "e2", "e3"}, snis("s"))
		b.rc.port.setRoll(func() bool { return false })
		b.rc.session.setDrop(func() bool { return false })

		seen := map[string]bool{}
		for i := 0; i < 60; i++ {
			ip, sni, _ := p.current()
			b.noteAttempt(ip, sni.host)
			low, high := b.livePairNow()
			b.tunFail(t, low, high)
			now, _, _ := p.current()
			seen[now] = true
		}
		for _, want := range []string{"e2", "e3"} {
			if !seen[want] {
				t.Errorf("edge %s was never reached in 60 verdicts; the pool only ever sat on %v", want, seen)
			}
		}
	})

	t.Run("direct pool", func(t *testing.T) {
		b, pp, _ := peerCarrier(t, []string{"d1:443", "d2:443", "d3:443"}, nil)
		b.rc.port.setRoll(func() bool { return false })
		b.rc.session.setDrop(func() bool { return false })

		seen := map[string]bool{}
		for i := 0; i < 60; i++ {
			b.noteAttempt(pp.current(), "")
			low, high := b.livePairNow()
			b.tunFail(t, low, high)
			seen[pp.current()] = true
		}
		for _, want := range []string{"d2:443", "d3:443"} {
			if !seen[want] {
				t.Errorf("peer %s was never reached in 60 verdicts; the pool only ever sat on %v", want, seen)
			}
		}
	})
}

// The other half of the same latch: it must stay shut for as long as the ladder has not answered the
// accusation, or the guard in one_outage_one_accused_test.go goes with it. A dial that is redirected
// without the ladder walking -- a retry landing back on the healthy edge -- may not rename the
// outage.
func TestARedirectedDialDoesNotRenameTheOutage(t *testing.T) {
	const good, dead, sni = "good:443", "dead:443", "front-a"
	b, _ := edgeCarrier(t, []string{good, dead}, snis(sni))

	b.pretendDown()
	b.noteAttempt(dead, sni)
	b.noteAttempt(good, sni)

	if low, _ := b.livePairNow(); low != dead {
		t.Fatalf("the outage is published as %q; it opened on %q and the ladder has not stepped off it, "+
			"so nothing may have renamed it", low, dead)
	}
}
