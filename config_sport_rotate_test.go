package main

import (
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

// raw_sport_rotate is the operator switch for per-packet source-port cycling. It only means anything on
// the udp profile: every other profile either forges no L4 ports at all, or (tcp) carries flow state that
// a mid-stream port change would break. Accepting it there would look enabled and silently do nothing.
func TestRawSportRotateNeedsAProfileThatForgesPorts(t *testing.T) {
	for _, p := range []string{"udp", "tcp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 5
		if err := c.validate(); err != nil {
			t.Fatalf("raw_sport_rotate on the %s profile rejected: %v — udp and tcp both forge a port "+
				"pair, so the rotation is one feature over both", p, err)
		}
	}

	for _, p := range []string{"bare", "esp", "ah", "l2tpv3", "icmp", "gre", "ipip", "etherip", "ipcomp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 5
		if err := c.validate(); err == nil {
			t.Errorf("raw_sport_rotate accepted on raw_profile %q, which builds no L4 header to put a "+
				"port in, so the walk would move a number nothing carries", p)
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
func TestRawSportRotateRidesWithFec(t *testing.T) {
	for _, p := range []string{"udp", "tcp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 5
		c.Fec = true
		if err := c.validate(); err != nil {
			t.Errorf("raw_sport_rotate with fec on %s rejected: %v. The pair was refused on the claim "+
				"that the FEC send path does not cycle the source port; it goes through wire() and "+
				"always has. Measured at 20%% loss: 254 Mbit with both, 132 with rotation alone.", p, err)
		}
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

// The edges are derived from packet.MaxDports, never written down. A test that says "9 is too many"
// keeps passing for the wrong reason the day the ceiling moves: it stops testing the edge and starts
// testing a number in the middle of the allowed range.
func TestRawDportsRange(t *testing.T) {
	for _, n := range []int{1, 2, packet.MaxDports - 1, packet.MaxDports} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = 4
		c.RawDports = n
		if err := c.validate(); err != nil {
			t.Errorf("raw_dports=%d rejected: %v", n, err)
		}
	}
	for _, n := range []int{-1, packet.MaxDports + 1, packet.MaxDports + 92} {
		c := validRaw()
		c.RawProfile = "udp"
		c.RawSportRotate = 4
		c.RawDports = n
		if err := c.validate(); err == nil {
			t.Errorf("raw_dports=%d accepted, want rejected", n)
		}
	}
}

// The band and the destination spread are two rules with two different preconditions: the band needs
// the source port to MOVE (either clock), the spread needs the ROTATION clock specifically. Stating
// them as one chained decision let one arm shadow the other, so each cell is asserted on its own.
func TestTheBandAndTheSpreadHaveTheirOwnPreconditions(t *testing.T) {
	band := func(lo, hi int) *Config {
		c := validRaw()
		c.RawProfile = "tcp"
		c.SportLo, c.SportHi = lo, hi
		return c
	}
	if err := band(10000, 44999).validate(); err != nil {
		t.Errorf("a band on a carrier whose source port only moves on the repair rung was rejected: %v."+
			" Every carrier draws its source port from this band now, so it always means something", err)
	}
	c := band(10000, 44999)
	c.RawSportRandom = true
	if err := c.validate(); err != nil {
		t.Errorf("a band under the reactive clock was rejected: %v", err)
	}
	c = band(10000, 44999)
	c.RawSportRotate = 6
	if err := c.validate(); err != nil {
		t.Errorf("a band under the rotation clock was rejected: %v", err)
	}
	for _, b := range [][2]int{
		{500, 44999},                                 // reaches into the privileged ports
		{packet.MinSportBandLo - 1, 44999},           // one below the floor
		{30000, 30000 + packet.MinSportBandSpan - 2}, // one short of the span floor
		{50000, 40000},                               // inverted
		{10000, 70000},                               // past the last port
		{10000, 0},                                   // half a range
		{0, 44999},                                   // the other half
	} {
		c := band(b[0], b[1])
		c.RawSportRotate = 6
		if err := c.validate(); err == nil {
			t.Errorf("band %d..%d was accepted", b[0], b[1])
		}
	}
	// exactly the two floors is legal
	c = band(packet.MinSportBandLo, packet.MinSportBandLo+packet.MinSportBandSpan-1)
	c.RawSportRotate = 6
	if err := c.validate(); err != nil {
		t.Errorf("the smallest legal band was rejected: %v", err)
	}
	// and the spread still refuses the reactive clock, which moves the port but not on a lap
	c = validRaw()
	c.RawProfile = "tcp"
	c.RawSportRandom = true
	c.RawDports = 4
	if err := c.validate(); err == nil {
		t.Error("a destination spread was accepted under the reactive clock, which has no lap to spread over")
	}
}

// The profile rule is inherited rather than restated: raw_dports rides on raw_sport_rotate, which is
// udp-only, so a non-udp profile must be refused through that gate and not silently allowed here.
func TestRawDportsFollowsWhereverTheRotationGoes(t *testing.T) {
	for _, p := range []string{"udp", "tcp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 4
		c.RawDports = 4
		if err := c.validate(); err != nil {
			t.Errorf("raw_dports rejected on %s: %v — it rides raw_sport_rotate, so it is available "+
				"exactly where the rotation is", p, err)
		}
	}

	for _, p := range []string{"bare", "esp", "ah", "l2tpv3", "icmp"} {
		c := validRaw()
		c.RawProfile = p
		c.RawSportRotate = 4
		c.RawDports = 4
		if err := c.validate(); err == nil {
			t.Errorf("raw_dports accepted on raw_profile %q, want rejected", p)
		}
	}
}
