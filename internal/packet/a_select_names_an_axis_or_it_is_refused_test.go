//go:build linux

package packet

import "testing"

// peerPair.axis matched the HIGH kind and returned the destination pool for everything else, so any
// kind the pair does not own -- a typo, or a ws pool's "ip"/"sni" vocabulary arriving at a direct
// pair's "dst"/"src" one -- silently steered the destination axis instead of being refused.
//
// Traced end to end before changing it, this is NOT reachable from the panel today: op_peer_select
// writes dst/src and is gated on a peer pool, op_pool_select writes ip/sni and is gated on a ws pool,
// and op_retest_now validates all four and gates ip/sni to ws pools. Nothing in production can send a
// pair a kind it does not own. What is under test here is the pool's own answer, so the next caller
// cannot reintroduce the silent fallthrough.
func TestEveryCarrierRefusesASelectForAnAxisItDoesNotHave(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		want := rigDsts[len(rigDsts)-1]
		lowWas, highWas := r.live()
		if want == lowWas {
			t.Fatalf("%s: the rig starts on the entry the test wants to move to", r.name)
		}
		r.low.markSuspect(want, "test")

		for _, kind := range []string{"", "not-an-axis", "DST", r.lowKind + "x"} {
			r.deliver(t, poolCmd{Kind: kind, Key: want})

			if now, _ := r.live(); now != lowWas {
				t.Errorf("%s: a select for kind %q moved the %s axis from %q to %q",
					r.name, kind, r.lowKind, lowWas, now)
			}
			if !burned(r.low, want) {
				t.Errorf("%s: a select for kind %q pardoned %q on the %s axis",
					r.name, kind, want, r.lowKind)
			}
			if _, now := r.live(); now != highWas {
				t.Errorf("%s: a select for kind %q moved the %s axis", r.name, kind, r.highKind)
			}
		}
	})
}

// A retest for an axis the pair does not own must be refused the same way, and must not end the wait
// on a destination that happens to share the key.
func TestEveryCarrierRefusesARetestForAnAxisItDoesNotHave(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		low, _ := r.live()
		r.low.markSuspect(low, "test")
		if eligible(r.low, low) {
			t.Fatalf("%s: setup left the entry eligible", r.name)
		}

		r.deliver(t, poolCmd{Cmd: cmdRetest, Kind: "not-an-axis", Key: low})

		if eligible(r.low, low) {
			t.Errorf("%s: a retest naming no axis of this pair still ended the wait on %q",
				r.name, low)
		}
	})
}

// The two kinds the pair DOES own keep working, or the guard above has just broken the operator.
func TestEveryCarrierStillAnswersForBothOfItsOwnAxes(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		low, high := r.live()
		r.low.markSuspect(low, "test")
		r.high.markSuspect(high, "test")

		r.deliver(t, poolCmd{Cmd: cmdRetest, Kind: r.lowKind, Key: low})
		if !eligible(r.low, low) {
			t.Errorf("%s: a retest on its own low kind %q was refused", r.name, r.lowKind)
		}

		r.deliver(t, poolCmd{Cmd: cmdRetest, Kind: r.highKind, Key: high})
		if !eligible(r.high, high) {
			t.Errorf("%s: a retest on its own high kind %q was refused", r.name, r.highKind)
		}
	})
}
