package packet

import "testing"

func TestTheLapIsSizedOnceAndNotReReadAsItShrinks(t *testing.T) {
	var o odometer
	left := 3
	shrinking := func() int { n := left; left--; return n }

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

func TestNothingEligibleStillCountsAsOneRound(t *testing.T) {
	var o odometer
	if !o.failed(func() int { return 0 }) {
		t.Error("with nothing eligible the single entry in play is the whole lap, so one round completes it")
	}
	if o.rot != 0 {
		t.Errorf("the round must reset after it completes, rot=%d", o.rot)
	}
}

func TestAProactiveLapRestartsTheFailoverRound(t *testing.T) {
	var o odometer
	three := func() int { return 3 }

	if o.failed(three) {
		t.Fatal("one of three rounds must not complete the lap")
	}
	if o.rot != 1 {
		t.Fatalf("expected one round banked, rot=%d", o.rot)
	}

	if !o.beat(false, three) {
		t.Fatal("a low axis that cannot move has been all the way round")
	}
	if o.rot != 0 {
		t.Errorf("the high axis moved and the failover round survived it (rot=%d) — the next round "+
			"would convict a high entry the walk never finished testing", o.rot)
	}
}

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

func TestRestartClearsTheRoundAndLeavesTheSchedule(t *testing.T) {
	var o odometer
	three := func() int { return 3 }
	o.failed(three)
	o.beat(true, three)

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
