package packet

import (
	"path/filepath"
	"testing"
	"time"
)

// Move the armed wait into the past, so the next verdict finds it up. The length of the wait is the
// operator's; what these tests need is the moment after it, without spending it in wall clock.
func elapse(rc *rotationController) {
	rc.revive.mu.Lock()
	rc.revive.at = time.Now().Add(-time.Second)
	rc.revive.mu.Unlock()
}

// How long the ladder is currently waiting before it may climb again.
func armedFor(rc *rotationController) time.Duration {
	rc.revive.mu.Lock()
	defer rc.revive.mu.Unlock()
	return time.Until(rc.revive.at).Round(time.Second)
}

// Drive verdicts until every rung is spent and the walk has found nowhere to go. The dead end is the
// first verdict that moves NEITHER counter; a fixed count would instead assume the ladder started full,
// which is only true of the first climb.
func toDeadEnd(t *testing.T, rc *rotationController, rolls, drops *int, rot func(bool)) {
	t.Helper()
	for i := 0; i < 4*portTries+16; i++ {
		r, d := *rolls, *drops
		failLivePair(t, rc, noRot, rot)
		if *rolls == r && *drops == d {
			return
		}
	}
	t.Fatalf("the ladder never dead-ended: %d draws, %d handshakes", *rolls, *drops)
}

// The ladder a stuck raw client actually has: no destination pool, one source, nowhere to walk. Every
// rung is spent within seconds of the outage and nothing above the ladder ever begins another climb --
// so a path whose only fault is the port it last drew stayed down until the process was restarted.
// Measured in production: one tunnel spent 3 rungs and then rode out 3480 further verdicts changing
// nothing.
func TestAnExhaustedLadderIsHandedBackAfterItsWait(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	toDeadEnd(t, rc, rolls, drops, rot)
	spentRolls, spentDrops := *rolls, *drops
	if spentRolls != portTries || spentDrops != 1 {
		t.Fatalf("setup: want the whole ladder spent (%d draws, 1 handshake), got %d and %d",
			portTries, spentRolls, spentDrops)
	}

	elapse(rc)
	failLivePair(t, rc, noRot, rot) // finds the wait up: hands the rungs back, spends none of them
	if *rolls != spentRolls {
		t.Errorf("the verdict that revives the ladder also spent a rung (%d draws, want %d) -- the "+
			"first rung tears the carrier down, so spending one here manufactures the next outage",
			*rolls, spentRolls)
	}
	toDeadEnd(t, rc, rolls, drops, rot)
	if *rolls != 2*portTries || *drops != 2 {
		t.Errorf("after the wait the ladder must climb again in full: %d draws / %d handshakes, "+
			"want %d / 2", *rolls, *drops, 2*portTries)
	}
}

// The mutation control for the test above: the SAME dead end, the SAME verdicts, only the wait not yet
// up. Nothing may be handed back. Without this, a ladder that refilled unconditionally would pass the
// test above while redrawing the source port every couple of seconds for the life of the process.
func TestTheLadderStaysDeadUntilItsWaitIsUp(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	toDeadEnd(t, rc, rolls, drops, rot)
	for i := 0; i < 60; i++ { // a minute of the node's probe, inside the first wait
		failLivePair(t, rc, noRot, rot)
	}
	if *rolls != portTries || *drops != 1 {
		t.Errorf("the ladder was handed back before its wait: %d draws / %d handshakes, want %d / 1",
			*rolls, *drops, portTries)
	}
}

// Each dead end waits longer than the one before, and the last entry repeats. This is what keeps a path
// that is simply gone from being churned: the first retry is quick enough for a peer that only rebooted,
// and the steady state is one climb per last entry.
func TestEachDeadEndWaitsLongerThanTheLast(t *testing.T) {
	restore := ladderRevive
	ladderRevive = []int64{2, 5, 9}
	t.Cleanup(func() { ladderRevive = restore })

	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	var got []time.Duration
	for round := 0; round < 4; round++ {
		toDeadEnd(t, rc, rolls, drops, rot)
		got = append(got, armedFor(rc))
		elapse(rc)
		failLivePair(t, rc, noRot, rot)
	}
	want := []time.Duration{2 * time.Second, 5 * time.Second, 9 * time.Second, 9 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dead end %d waits %v, want %v (whole sequence %v)", i+1, got[i], want[i], got)
		}
	}
}

// Only a MEASURED recovery forgives the backoff. A tunnel that came back and later failed again is a
// new outage and deserves the quick first retry; carrying it over would leave a tunnel that had one bad
// hour waiting the longest step for the rest of the process.
func TestCarryingForgivesTheBackoff(t *testing.T) {
	restore := ladderRevive
	ladderRevive = []int64{2, 5, 9}
	t.Cleanup(func() { ladderRevive = restore })

	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) }

	toDeadEnd(t, rc, rolls, drops, rot)
	elapse(rc)
	failLivePair(t, rc, noRot, rot)
	if w := armedFor(rc); w != 5*time.Second {
		t.Fatalf("setup: the backoff should have walked to 5s, got %v", w)
	}

	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdOK, Low: low, High: high})
	rc.poll(noRot, rot, nil, rc.st.pathEpoch)

	toDeadEnd(t, rc, rolls, drops, rot)
	if w := armedFor(rc); w != 2*time.Second {
		t.Errorf("after traffic crossed, the next dead end waits %v -- want the FIRST step (2s), "+
			"because a recovered tunnel that fails again is a new outage", w)
	}
}

// The wait is the operator's number, not a constant. Without this the knob travels through panel, node
// and config and is then ignored by the one line that matters.
func TestTheReviveWaitIsTheOperatorsNumber(t *testing.T) {
	restore := ladderRevive
	t.Cleanup(func() { ladderRevive = restore })

	ApplyTuning(TuningInput{LadderRevive: []int64{7}})
	if len(ladderRevive) != 1 || ladderRevive[0] != 7 {
		t.Fatalf("ApplyTuning did not take the wait: %v", ladderRevive)
	}
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	toDeadEnd(t, rc, rolls, drops, func(bool) { src.nextEndpoint(false) })
	if w := armedFor(rc); w != 7*time.Second {
		t.Errorf("the ladder waits %v, want the operator's 7s", w)
	}
}

// Junk never replaces the compiled-in wait -- an empty or out-of-range list leaves the default standing
// rather than producing a ladder that revives instantly or never.
func TestAnUnusableReviveWaitKeepsTheDefault(t *testing.T) {
	restore := ladderRevive
	t.Cleanup(func() { ladderRevive = restore })

	for _, in := range [][]int64{nil, {}, {0}, {-3}, {86401}} {
		ladderRevive = []int64{45, 180, 600}
		ApplyTuning(TuningInput{LadderRevive: in})
		if len(ladderRevive) != 3 || ladderRevive[0] != 45 {
			t.Errorf("ApplyTuning(%v) replaced the default with %v", in, ladderRevive)
		}
	}
}

// Three ladder shapes exist, and no carrier installs both rungs unconditionally: raw with a random
// source port gets the draw and the handshake, tcp/ws gets only the draw, and udp, flux and raw on a
// fixed port get only the handshake. The revive sits under spendFreeRungs and cannot see which rungs it
// has, so prove it on each rather than on the one shape the tests above happen to use.
func TestTheReviveWorksOnEveryLadderShape(t *testing.T) {
	for _, tc := range []struct {
		name       string
		roll, drop bool
	}{
		{"raw with a random source port: draw and handshake", true, true},
		{"tcp/ws: draws only", true, false},
		{"udp, flux, raw on a fixed port: handshake only", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := NewPeerPool([]string{"94.182.131.47"}, 0)
			rc := newRotationController(nil, src)
			rolls, drops := new(int), new(int)
			budget := 0
			if tc.roll {
				rc.port.setRoll(func() bool { *rolls++; return true })
				budget += portTries
			}
			if tc.drop {
				rc.session.setDrop(func() bool { *drops++; return true })
				budget++
			}
			rc.attachStatus(newCoreStatus(filepath.Join(t.TempDir(), "core.status"), ""))
			rot := func(bool) { src.nextEndpoint(false) }

			toDeadEnd(t, rc, rolls, drops, rot)
			if spent := *rolls + *drops; spent != budget {
				t.Fatalf("setup: the ladder spent %d steps, want %d", spent, budget)
			}

			elapse(rc)
			failLivePair(t, rc, noRot, rot) // the wait is up: hands the rungs back, spends none
			if spent := *rolls + *drops; spent != budget {
				t.Errorf("the reviving verdict spent a rung: %d steps, want %d", spent, budget)
			}

			toDeadEnd(t, rc, rolls, drops, rot)
			if spent := *rolls + *drops; spent != 2*budget {
				t.Errorf("after its wait the ladder must climb again in full: %d steps, want %d",
					spent, 2*budget)
			}
		})
	}
}
