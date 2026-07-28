package main

import (
	"strings"
	"testing"
)

// TestEffectiveDeadAfterUsesTheCarriersOwnFloor guards the startup log against promising a self-heal
// deadline the carrier will not enforce. Every carrier floors dead_after_secs, but dns floors at its own
// ABSOLUTE window while the rest clamp to 2×keepalive — so the shared 2×keepalive arithmetic misreported
// dns in BOTH directions.
//
// This tests the helper the log line calls, and the call site is one line long: it logs exactly what the
// helper returns. What it does NOT prove is that the dns carrier's floor is the number dnstun applies —
// that link is DNSDeadFloorSecs reading dnstun.DeadFloor(), i.e. the same variable resolveKeepalive uses.
func TestEffectiveDeadAfterUsesTheCarriersOwnFloor(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		keepalive int
		deadAfter int
		want      int
	}{
		{"udp: the operator's value clears 2xkeepalive", "udp", 5, 30, 30},
		{"udp: below 2xkeepalive is floored there", "udp", 15, 10, 30},
		{"tcp: same rule", "tcp", 10, 5, 20},
		// The two shapes the old arithmetic got wrong. Both must land on the dns floor.
		{"dns: 2xkeepalive would OVERstate the window", "dns", 15, 10, 20},
		{"dns: 2xkeepalive would UNDERstate the window", "dns", 5, 10, 20},
		{"dns: a value above the floor is kept", "dns", 5, 45, 45},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note := effectiveDeadAfter(tc.transport, tc.keepalive, tc.deadAfter)
			if got != tc.want {
				t.Fatalf("effectiveDeadAfter(%q, ka=%d, dead=%d) = %d, want %d",
					tc.transport, tc.keepalive, tc.deadAfter, got, tc.want)
			}
			// The note must name the floor that actually applied, or the log explains the wrong rule.
			wantNote := "keepalive"
			if tc.transport == "dns" {
				wantNote = "dns carrier floor"
			}
			if !strings.Contains(note, wantNote) {
				t.Errorf("note %q does not name the floor in force (want it to mention %q)", note, wantNote)
			}
		})
	}
}

// TestFecRejectionNamesTheCarrier: the FEC rejection used to list "tcp/ws" only, so a dns tunnel was
// refused by a message that never mentioned dns and the operator could reasonably read it as belonging
// to a different tunnel. Every non-datagram carrier must see its own name in the error.
//
// Each case starts from a config that validates CLEAN on that transport and turns on nothing but fec, so
// a passing assertion cannot come from some unrelated rejection.
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
