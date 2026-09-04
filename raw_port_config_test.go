package main

import "testing"

func TestRawPortOnlyOnAProfileThatForgesPorts(t *testing.T) {
	for _, profile := range []string{"udp", "tcp"} {
		c := validRaw()
		c.RawProfile, c.RawPort = profile, 51820
		if err := c.validate(); err != nil {
			t.Errorf("raw/%s forges ports and must accept raw_port, got %v", profile, err)
		}
	}
	for _, profile := range []string{"bare", "", "icmp", "gre", "esp", "ipip"} {
		c := validRaw()
		c.RawProfile, c.RawPort = profile, 51820
		if err := c.validate(); err == nil {
			t.Errorf("raw/%q forges no ports — raw_port must be refused, not silently ignored", profile)
		}
	}
	for _, bad := range []int{-1, 65536} {
		c := validRaw()
		c.RawProfile, c.RawPort = "udp", bad
		if err := c.validate(); err == nil {
			t.Errorf("raw_port %d is out of range and must be refused", bad)
		}
	}

	for _, profile := range []string{"bare", "udp", "tcp", "icmp"} {
		c := validRaw()
		c.RawProfile, c.RawPort = profile, 0
		if err := c.validate(); err != nil {
			t.Errorf("raw/%s with no raw_port must validate, got %v", profile, err)
		}
	}
}
