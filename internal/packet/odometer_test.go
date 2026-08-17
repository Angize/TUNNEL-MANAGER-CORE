package packet

import "testing"

// TestTheLapIsSizedOnceAndNotReReadAsItShrinks.
//
// Every round burns one entry, so the eligible count falls as the walk proceeds. Sizing the lap again
// on each round compares against a number that is one smaller every time, and three entries declare a
// full lap after two — convicting the high axis a round early, on evidence that was never gathered.
func TestTheLapIsSizedOnceAndNotReReadAsItShrinks(t *testing.T) {
	var o odometer
	left := 3
	shrinking := func() int { n := left; left--; return n } // what a burn per round looks like

	for round := 1; round <= 2; round++ {
		if o.failed(shrinking) {
			t.Fatalf("round %d of 3 moved the high axis: the lap was re-sized as it shrank", round)
		}
	}
	if !o.failed(shrinking) {
		t.Error("the third of three rounds must move the high axis — every entry has now been tried")
	}
	if calls := 3 - left; calls != 1 {
		t.Errorf("the lap was sized %d times in one round, want exactly once", calls)
	}
}

// TestNothingEligibleStillCountsAsOneRound.
//
// With every entry condemned the walk has nothing to try, but the entry it is sitting on is still the
// experiment, so one round completes the lap and the high axis moves.
//
// This does NOT cover the "floor the lap at one" branch the three copies carried: that branch cannot
// change any outcome — 1 >= 0 and 1 >= 1 are both true — which is why it is gone rather than pinned.
func TestNothingEligibleStillCountsAsOneRound(t *testing.T) {
	var o odometer
	if !o.failed(func() int { return 0 }) {
		t.Error("with nothing eligible the single entry in play is the whole lap, so one round completes it")
	}
	if o.rot != 0 {
		t.Errorf("the round must reset after it completes, rot=%d", o.rot)
	}
}

// TestAProactiveLapRestartsTheFailoverRound.
//
// The failover count means "every low entry tried against THIS high one", so it cannot survive the
// high one moving. One of the three copies this replaces reset it here and the other left it to a
// teardown path that a failed warm build never reaches — so the count carried over onto a source the
// walk had not tested, and the next round could convict it early.
func TestAProactiveLapRestartsTheFailoverRound(t *testing.T) {
	var o odometer
	three := func() int { return 3 }

	if o.failed(three) { // one failover round banked against the current high entry
		t.Fatal("one of three rounds must not complete the lap")
	}
	if o.rot != 1 {
		t.Fatalf("expected one round banked, rot=%d", o.rot)
	}

	if !o.beat(false, three) { // the low axis could not move: a lap, so the high one follows
		t.Fatal("a low axis that cannot move has been all the way round")
	}
	if o.rot != 0 {
		t.Errorf("the high axis moved and the failover round survived it (rot=%d) — the next round "+
			"would convict a high entry the walk never finished testing", o.rot)
	}
}

// TestABeatOnAnImmovableAxisAsksNothing.
//
// `eligible` takes the pool's lock, and a low axis that did not move is already a lap whatever the
// count says. Reading it anyway is a lock taken to answer a question with only one answer.
func TestABeatOnAnImmovableAxisAsksNothing(t *testing.T) {
	var o odometer
	asked := 0
	if !o.beat(false, func() int { asked++; return 5 }) {
		t.Error("an axis that could not move must lap")
	}
	if asked != 0 {
		t.Errorf("the eligible count was read %d times for a beat that could not have used it", asked)
	}
}

// TestRestartClearsTheRoundAndLeavesTheSchedule.
//
// A live carrier invalidates the failover round — whatever it proved is stale. The proactive beat is
// not a round though, it is a schedule, and resetting it here would stretch the interval every time a
// tunnel recovered.
func TestRestartClearsTheRoundAndLeavesTheSchedule(t *testing.T) {
	var o odometer
	three := func() int { return 3 }
	o.failed(three)
	o.beat(true, three) // one beat banked, not yet a lap

	tick := o.tick
	if tick == 0 {
		t.Fatal("expected a beat to be banked")
	}
	o.restart()
	if o.rot != 0 || o.want != 0 {
		t.Errorf("restart left the failover round behind: rot=%d want=%d", o.rot, o.want)
	}
	if o.tick != tick {
		t.Errorf("restart moved the proactive schedule from %d to %d — it is a schedule, not a round",
			tick, o.tick)
	}
}
