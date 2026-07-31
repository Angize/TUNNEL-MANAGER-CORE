package packet

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
)

// The dns carrier publishes `dw` into the status file and the panel calls a tunnel dead once hb is
// that many seconds old. The number therefore has to be the one the SESSION re-dials on — and the
// carrier had re-derived its own version of the rule, keeping dnstun's absolute floor and dropping the
// keepaliveDeadMult×keepalive term entirely. At the shipped defaults (keepalive=15s, no
// dead_after_secs) it published 20 against a real 45: a healthy dns tunnel reads as dead 25 seconds
// early, so one dropped ping — on the carrier whose whole justification is surviving several — turns
// the dot red while traffic is flowing.
//
// The numbers below are written from the RULE, not from either implementation, so this stays a real
// assertion if someone re-derives the window a third time. The existing e2e (dns_status_test.go) could
// not catch it: it dials with keepalive=1s, the one region where 3×keepalive is under the 20s floor and
// both formulas coincide, and it only asserts dw >= the floor.
func TestDNSPublishesTheWindowTheSessionEnforces(t *testing.T) {
	for _, tc := range []struct {
		name      string
		keepalive time.Duration
		deadAfter int
		want      time.Duration
	}{
		{"shipped defaults: 3x15s", 15 * time.Second, 0, 45 * time.Second},
		{"dnstun's own default keepalive", 0, 0, 30 * time.Second},
		{"3xkeepalive under the floor", 5 * time.Second, 0, 20 * time.Second},
		{"3xkeepalive exactly at the floor", 20 * time.Second / 3, 0, 20 * time.Second},
		{"operator override below the floor is floored", 15 * time.Second, 10, 20 * time.Second},
		{"operator override above the floor wins", 15 * time.Second, 90, 90 * time.Second},
		{"operator override below 3xkeepalive still wins", 60 * time.Second, 30, 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Through the real constructor and the real knob setter, not by hand-filling cfg: the bug
			// lived in what the carrier does with what those two store.
			d, err := DialDNS(nil, []string{"127.0.0.1:53"}, "t.example.com", "psk-for-the-dead-window-test", "aes-256-gcm", tc.keepalive)
			if err != nil {
				t.Fatalf("DialDNS: %v", err)
			}
			if tc.deadAfter > 0 {
				d.SetDeadAfter(tc.deadAfter)
			}
			if got := d.deadWin(); got != tc.want {
				t.Errorf("published dead window %v, but the session re-dials at %v — the panel calls a live tunnel dead %v early",
					got, tc.want, tc.want-got)
			}
		})
	}
}

// ...and the same claim end to end, against the window the LIVE session is really holding rather than
// against a table. This is the half a formula test cannot give: it runs a real client into a real
// authoritative server, reads the file the node reads, and compares it with the number the keepalive
// goroutine was started with. keepalive is 15s — the shipped default, and the region where the two
// formulas disagreed — but nothing here waits for a ping: dw is published at Run and the session
// establishes over loopback immediately.
func TestDNSPublishedWindowMatchesTheLiveSession(t *testing.T) {
	const (
		psk  = "e2e-shared-pre-shared-key-1234567890"
		zone = "t.example.com"
	)
	addr := freeUDPPort(t)
	srvDev, _ := tunPair(t, "dnsdws")
	cliDev, _ := tunPair(t, "dnsdwc")

	srv, err := ListenDNS(srvDev, addr, zone, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenDNS: %v", err)
	}
	cli, err := DialDNS(cliDev, []string{addr}, zone, psk, "aes-256-gcm", 15*time.Second)
	if err != nil {
		t.Fatalf("DialDNS: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	var live net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cp := cli.conn.Load(); cp != nil {
			live = *cp
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if live == nil {
		t.Fatal("no dns session came up over loopback")
	}
	lw, ok := live.(interface{ DeadWindow() time.Duration })
	if !ok {
		t.Fatal("the live session exposes no DeadWindow — the carrier cannot publish what it enforces")
	}
	enforced := lw.DeadWindow()
	if enforced <= 0 {
		t.Fatal("the live client session reports a zero dead window")
	}

	var published int64
	for time.Now().Before(deadline) {
		b, rerr := os.ReadFile(statusPath)
		if rerr == nil {
			var doc struct {
				DW int64 `json:"dw"`
			}
			if json.Unmarshal(b, &doc) == nil && doc.DW > 0 {
				published = doc.DW
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if published == 0 {
		t.Fatalf("no dead window published at %s", statusPath)
	}
	if want := int64(enforced / time.Second); published != want {
		t.Errorf("status file says dw=%ds, the live session re-dials at %ds: the panel ages hb against a window nothing applies",
			published, want)
	}
	// And the number itself, so a change that makes both sides agree on something absurd is still caught.
	if want := int64(dnstun.ResolveDeadWindow(15*time.Second, 0) / time.Second); published != want {
		t.Errorf("dw=%ds at keepalive=15s, want %ds", published, want)
	}
}
