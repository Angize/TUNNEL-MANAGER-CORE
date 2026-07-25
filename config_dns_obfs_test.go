package main

import "testing"

// TestObfsRejectedOnDNS guards a silent no-op: obfs validated, persisted and displayed as enabled on a
// dns tunnel while doing nothing at all, because main.go's dns case calls ListenDNS/DialDNS — whose
// signatures take no obfs flag — and nothing in internal/dnstun references it. Every other carrier is
// handed cfg.Obfs. Rejecting the combination turns false assurance about anti-DPI framing, on the most
// sensitive carrier there is, into a build-time error.
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

	if err := dns().validate(); err != nil { // the same config without obfs stays valid
		t.Fatalf("dns without obfs must remain valid: %v", err)
	}

	c = dns() // ...and obfs must still be accepted on a carrier that actually implements it
	c.Transport, c.Peer = "udp", "1.2.3.4:9000"
	c.Obfs = true
	if err := c.validate(); err != nil {
		t.Fatalf("obfs on udp must remain valid: %v", err)
	}
}
