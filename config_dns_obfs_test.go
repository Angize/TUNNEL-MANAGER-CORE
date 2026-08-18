package main

import "testing"

func TestObfsRejectedOnDNS(t *testing.T) {
	dns := func() *Config {
		return &Config{Role: "client", Mode: "packet", Profile: "core", Transport: "dns",
			TunAddr: "10.0.0.1/24", DNSZone: "t.tnl", DNSResolvers: []string{"1.1.1.1"},
			Crypto: CryptoCfg{Enabled: true, PSK: "x"}}
	}

	c := dns()
	c.Obfs = true
	if err := c.validate(); err == nil {
		t.Fatal("obfs on the dns transport must be rejected — it silently does nothing")
	}

	if err := dns().validate(); err != nil {
		t.Fatalf("dns without obfs must remain valid: %v", err)
	}

	c = dns()
	c.Transport, c.Peer = "udp", "1.2.3.4:9000"
	c.Obfs = true
	if err := c.validate(); err != nil {
		t.Fatalf("obfs on udp must remain valid: %v", err)
	}
}
