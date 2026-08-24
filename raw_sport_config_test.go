package main

import "testing"

func TestRawSportOnlyOnAProfileThatForgesPorts(t *testing.T) {
	for _, profile := range []string{"udp", "tcp"} {
		c := validRaw()
		c.RawProfile, c.RawSport = profile, 4500
		if err := c.validate(); err != nil {
			t.Errorf("raw/%s forges ports and must accept raw_sport, got %v", profile, err)
		}
	}
	for _, profile := range []string{"bare", "", "icmp", "gre", "esp", "ipip"} {
		c := validRaw()
		c.RawProfile, c.RawSport = profile, 4500
		if err := c.validate(); err == nil {
			t.Errorf("raw/%q forges no ports — raw_sport must be refused, not silently ignored", profile)
		}
	}
	for _, bad := range []int{-1, 65536} {
		c := validRaw()
		c.RawProfile, c.RawSport = "udp", bad
		if err := c.validate(); err == nil {
			t.Errorf("raw_sport %d is out of range and must be refused", bad)
		}
	}
	for _, profile := range []string{"bare", "udp", "tcp", "icmp"} {
		c := validRaw()
		c.RawProfile, c.RawSport = profile, 0
		if err := c.validate(); err != nil {
			t.Errorf("raw/%s with no raw_sport must validate, got %v", profile, err)
		}
	}
}

// A number and a dice roll are two answers to one question. Accepting both would leave the operator
// reading a source port off a form while the wire carries something else entirely.
func TestRawSportAndRawSportRandomAreExclusive(t *testing.T) {
	c := validRaw()
	c.RawProfile, c.RawSport, c.RawSportRandom = "tcp", 4500, true
	if err := c.validate(); err == nil {
		t.Error("a fixed raw_sport together with raw_sport_random must be refused")
	}
	c.RawSportRandom = false
	if err := c.validate(); err != nil {
		t.Errorf("a fixed raw_sport alone must validate, got %v", err)
	}
	c.RawSport, c.RawSportRandom = 0, true
	if err := c.validate(); err != nil {
		t.Errorf("raw_sport_random alone must validate, got %v", err)
	}
}

func TestSpoofRefusesRawSport(t *testing.T) {
	c := validSpoof()
	c.RawSport = 4500
	if err := c.validate(); err == nil {
		t.Error("spoof writes no L4 header — raw_sport must be refused, not accepted and ignored")
	}
	c.RawSport = 0
	if err := c.validate(); err != nil {
		t.Errorf("spoof with no raw_sport must still validate, got %v", err)
	}
}
