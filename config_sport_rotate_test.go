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
	for _, n := range []int{1, 6, 64} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = n
		if err := c.validate(); err != nil {
			t.Errorf("raw_sport_rotate=%d rejected: %v", n, err)
		}
	}
	for _, n := range []int{-1, 65, 1000} {
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

func TestRawSportRotateRejectedOnSpoof(t *testing.T) {
	c := validSpoof()
	c.RawSportRotate = 5
	if err := c.validate(); err == nil {
		t.Error("raw_sport_rotate accepted on the spoof carrier, which writes no L4 header")
	}
}
