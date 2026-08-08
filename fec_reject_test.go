package main

import (
	"strings"
	"testing"
)

// TestFecRejectionNamesTheCarrier: the FEC rejection listed "tcp/ws" only, so a dns tunnel was refused
// by a message that never mentioned dns and could reasonably be read as belonging to another tunnel.
// Every non-datagram carrier must see its own name in the error. Each case starts from a config that
// validates CLEAN on that transport and turns on nothing but fec, so a pass cannot come from elsewhere.
func TestFecRejectionNamesTheCarrier(t *testing.T) {
	build := map[string]func() *Config{
		"dns": func() *Config {
			c := validRaw()
			c.Transport, c.DNSZone, c.DNSResolvers = "dns", "t.example.com", []string{"10.0.0.1"}
			return c
		},
		"tcp": func() *Config {
			c := validRaw()
			c.Transport = "tcp"
			c.Peer = "203.0.113.9:443"
			return c
		},
		"ws": func() *Config {
			c := validRaw()
			c.Transport, c.WSHost = "ws", "cdn.example.com"
			c.Peer = "203.0.113.9:443"
			return c
		},
	}
	for transport, mk := range build {
		t.Run(transport, func(t *testing.T) {
			if err := mk().validate(); err != nil {
				t.Fatalf("precondition: the %s config must be valid before fec is added, got %v", transport, err)
			}
			c := mk()
			c.Fec, c.FecData, c.FecParity = true, 10, 3
			err := c.validate()
			if err == nil {
				t.Fatalf("fec must be rejected on the %s carrier", transport)
			}
			if !strings.Contains(err.Error(), "fec") {
				t.Fatalf("rejected for an unrelated reason, so this proves nothing about the fec message: %q", err)
			}
			if !strings.Contains(err.Error(), transport) {
				t.Errorf("the fec rejection never names the carrier the operator configured: %q", err)
			}
		})
	}
}
