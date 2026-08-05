package main

import "testing"

// TestRawPortOnlyOnAProfileThatForgesPorts is the mirror of the raw_proto rule. A knob accepted on a
// profile that ignores it is worse than one refused: it validates, persists, and reads back as set
// while the wire keeps 443 — the operator believes the carrier moved off QUIC's port and it did not.
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
	// 0 is "unset" and must stay legal on every profile, or an untouched tunnel stops validating.
	for _, profile := range []string{"bare", "udp", "tcp", "icmp"} {
		c := validRaw()
		c.RawProfile, c.RawPort = profile, 0
		if err := c.validate(); err != nil {
			t.Errorf("raw/%s with no raw_port must validate, got %v", profile, err)
		}
	}
}

// TestSpoofRefusesRawPort: spoof is headerless by definition — it forges no L4 header, so there is no
// port in it to override. Accepting raw_port there is the same silent no-op the raw case refuses, one
// transport tab away.
func TestSpoofRefusesRawPort(t *testing.T) {
	c := validSpoof()
	c.RawPort = 51820
	if err := c.validate(); err == nil {
		t.Error("spoof writes no L4 header — raw_port must be refused, not accepted and ignored")
	}
	c.RawPort = 0
	if err := c.validate(); err != nil {
		t.Errorf("spoof with no raw_port must still validate, got %v", err)
	}
}
