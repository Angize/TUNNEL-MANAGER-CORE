package main

import "testing"

// raw_sport_rotate is the operator switch for per-packet source-port cycling. It only means anything on
// the udp profile: every other profile either forges no L4 ports at all, or (tcp) carries flow state that
// a mid-stream port change would break. Accepting it there would look enabled and silently do nothing.
func TestRawSportRotateAcceptedOnUDPOnly(t *testing.T) {
	c := validRaw()
	c.RawProfile = "udp"
	c.RawSportRotate = 5
	if err := c.validate(); err != nil {
		t.Fatalf("raw_sport_rotate on the udp profile rejected: %v", err)
	}

	for _, p := range []string{"bare", "tcp", "esp", "ah", "l2tpv3", "icmp", "gre"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 5
		if err := c.validate(); err == nil {
			t.Errorf("raw_sport_rotate accepted on raw_profile %q, want rejected", p)
		}
	}
}

func TestRawSportRotateRange(t *testing.T) {
	for _, n := range []int{1, 6, maxSportEvery} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = n
		if err := c.validate(); err != nil {
			t.Errorf("raw_sport_rotate=%d rejected: %v", n, err)
		}
	}
	for _, n := range []int{-1, maxSportEvery + 1, 1000} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = n
		if err := c.validate(); err == nil {
			t.Errorf("raw_sport_rotate=%d accepted, want rejected", n)
		}
	}
}

// Cycling the source port continuously cannot coexist with the two knobs that pin or roll it once --
// whichever the operator set would be silently overwritten on the wire.
func TestRawSportRotateConflictsWithTheOtherSourcePortKnobs(t *testing.T) {
	c := validRaw()
	c.RawProfile = "udp"
	c.RawSportRotate = 5
	c.RawSport = 4500
	if err := c.validate(); err == nil {
		t.Error("raw_sport_rotate with raw_sport accepted, want rejected")
	}

	c = validRaw()
	c.RawProfile = "udp"
	c.RawSportRotate = 5
	c.RawSportRandom = true
	if err := c.validate(); err == nil {
		t.Error("raw_sport_rotate with raw_sport_random accepted, want rejected")
	}
}

// The FEC send path builds its frames off a snapshotted port, so rotation would not reach the wire there.
// Rejecting the pair is what keeps that from looking enabled while every packet leaves on one tuple.
func TestRawSportRotateRejectedWithFec(t *testing.T) {
	c := validRaw()
	c.RawProfile = "udp"
	c.RawSportRotate = 5
	c.Fec = true
	if err := c.validate(); err == nil {
		t.Error("raw_sport_rotate with fec accepted, want rejected")
	}
}

// raw_dports is the second axis of the same feature: it spreads the forged DESTINATION port so one
// source port is worth several flow-table buckets. On its own it means nothing -- with the source port
// pinned, every packet still shares one bucket per destination and the walk never moves -- so it is
// only accepted alongside raw_sport_rotate.
func TestRawDportsOnlyMeansSomethingWhileTheSourceIsCycling(t *testing.T) {
	c := validRaw()
	c.RawProfile = "udp"
	c.RawSportRotate = 4
	c.RawDports = 4
	if err := c.validate(); err != nil {
		t.Fatalf("raw_dports alongside raw_sport_rotate rejected: %v", err)
	}

	c = validRaw()
	c.RawProfile = "udp"
	c.RawDports = 4
	if err := c.validate(); err == nil {
		t.Error("raw_dports accepted with no raw_sport_rotate, want rejected")
	}
}

func TestRawDportsRange(t *testing.T) {
	for _, n := range []int{1, 2, 8} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = 4
		c.RawDports = n
		if err := c.validate(); err != nil {
			t.Errorf("raw_dports=%d rejected: %v", n, err)
		}
	}
	for _, n := range []int{-1, 9, 100} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = 4
		c.RawDports = n
		if err := c.validate(); err == nil {
			t.Errorf("raw_dports=%d accepted, want rejected", n)
		}
	}
}

// The profile rule is inherited rather than restated: raw_dports rides on raw_sport_rotate, which is
// udp-only, so a non-udp profile must be refused through that gate and not silently allowed here.
func TestRawDportsIsRefusedOffTheUDPProfile(t *testing.T) {
	for _, p := range []string{"bare", "tcp", "esp", "ah", "l2tpv3", "icmp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 4
		c.RawDports = 4
		if err := c.validate(); err == nil {
			t.Errorf("raw_dports accepted on raw_profile %q, want rejected", p)
		}
	}
}
