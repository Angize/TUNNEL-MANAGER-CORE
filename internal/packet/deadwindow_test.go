package packet

import (
	"testing"
	"time"
)

// TestEveryCarrierSharesOneDeadWindow pins the rule the whole self-heal story now rests on: ONE
// multiplier over keepalive, the same number on every carrier and on BOTH roles.
//
// It walks EVERY real constructor rather than the helper, and that is the point — the failure worth
// catching is a construction site that resolves its own window, or forgets one and leaves a zero window,
// which calls every session stale on its first check. Two sites out of nine would have said nothing
// about the other seven. dns is the deliberate exception: high-loss, so it floors at dnstun's own
// absolute window; TestDNSPublishesTheWindowTheSessionEnforces owns that rule.
func TestEveryCarrierSharesOneDeadWindow(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"

	for _, ka := range []time.Duration{5 * time.Second, 15 * time.Second, 40 * time.Second} {
		want := time.Duration(deadMult) * ka
		if got := deadWindow(ka); got != want {
			t.Fatalf("deadWindow(%v) = %v, want %v", ka, got, want)
		}

		// tcp/ws/http: the window IS the read deadline, and each end has one of its own. Every
		// constructor, both roles — a new one that forgets `idle` fails here rather than in production.
		streams := []struct {
			name string
			mk   func() (*TCP, error)
		}{
			{"DialTCP", func() (*TCP, error) {
				return DialTCP("203.0.113.9:443", nil, ka, false, false, psk, "aes-256-gcm", false, "")
			}},
			{"DialWS", func() (*TCP, error) {
				return DialWS("203.0.113.9:443", nil, ka, false, false, psk, "aes-256-gcm", "cdn.example.com", "/w", true, nil)
			}},
			{"DialWSPool", func() (*TCP, error) {
				return DialWSPool(nil, ka, false, false, psk, "aes-256-gcm", nil, 0, false, "")
			}},
			{"DialHTTPC", func() (*TCP, error) {
				return DialHTTPC("203.0.113.9:443", nil, ka, false, false, psk, "aes-256-gcm", "cdn.example.com", "/w", true, nil, "")
			}},
			{"ListenHTTPC", func() (*TCP, error) {
				return ListenHTTPC("127.0.0.1:0", nil, ka, false, false, psk, "aes-256-gcm")
			}},
			{"ListenWS", func() (*TCP, error) {
				return ListenWS("127.0.0.1:0", nil, ka, false, false, psk, "aes-256-gcm", "/w")
			}},
			{"ListenTCP", func() (*TCP, error) {
				return ListenTCP([]string{"127.0.0.1:0"}, nil, ka, false, false, psk, "aes-256-gcm", false, "")
			}},
		}
		for _, s := range streams {
			b, err := s.mk()
			if err != nil {
				t.Fatalf("ka=%v: %s: %v", ka, s.name, err)
			}
			if b.idle != want {
				t.Errorf("ka=%v: %s read deadline = %v, want %v — every end must reap on the same window",
					ka, s.name, b.idle, want)
			}
			b.Close()
		}

		// udp: the same window, resolved as the session-stale deadline instead of a read deadline.
		ucli, err := Dial("203.0.113.9:9000", nil, ka, false, false, psk, "aes-256-gcm", false, 0, 0)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		usrv, err := Listen([]string{"127.0.0.1:0"}, nil, ka, false, false, psk, "aes-256-gcm", false, 0, 0)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		for _, c := range []struct {
			role string
			win  time.Duration
		}{{"client", ucli.deadWin()}, {"server", usrv.deadWin()}} {
			if c.win != want {
				t.Errorf("ka=%v: udp %s dead window = %v, want %v", ka, c.role, c.win, want)
			}
		}
		ucli.Close()
		usrv.Close()
	}
}
