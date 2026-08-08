package packet

import (
	"testing"
	"time"
)

// TestEveryCarrierSharesOneDeadWindow pins the rule the whole self-heal story now rests on: ONE
// multiplier over keepalive, the same number on every carrier and on BOTH roles. It walks the real
// constructors rather than the helper, because the failure that matters is a construction site that
// resolves its own window — or forgets one, leaving a zero window that calls every session stale on
// its first check. dns is the deliberate exception: high-loss, so it floors at dnstun's own absolute
// window; TestDNSPublishesTheWindowTheSessionEnforces owns that rule.
func TestEveryCarrierSharesOneDeadWindow(t *testing.T) {
	for _, ka := range []time.Duration{5 * time.Second, 15 * time.Second, 40 * time.Second} {
		want := time.Duration(deadMult) * ka
		if got := deadWindow(ka); got != want {
			t.Fatalf("deadWindow(%v) = %v, want %v", ka, got, want)
		}

		// tcp/ws: the window IS the read deadline, and the server has one of its own.
		cli, err := DialTCP("203.0.113.9:443", nil, ka, false, false, "", "", false, "")
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		srv, err := ListenTCP([]string{"127.0.0.1:0"}, nil, ka, false, false, "", "", false, "")
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		for _, c := range []struct {
			role string
			win  time.Duration
		}{{"client", cli.idle}, {"server", srv.idle}} {
			if c.win != want {
				t.Errorf("ka=%v: tcp %s read deadline = %v, want %v — both ends must reap on the same window",
					ka, c.role, c.win, want)
			}
		}
		srv.Close()

		// udp: the same window, resolved as the session-stale deadline instead of a read deadline.
		ucli, err := Dial("203.0.113.9:9000", nil, ka, false, false, "", "", false, 0, 0)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		usrv, err := Listen([]string{"127.0.0.1:0"}, nil, ka, false, false, "", "", false, 0, 0)
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
