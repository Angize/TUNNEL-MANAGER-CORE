package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readUnans(path string) (unans, rt int64) {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1, -1
	}
	var d struct {
		U  int64 `json:"unanswered"`
		RT int64 `json:"rt"`
	}
	if json.Unmarshal(b, &d) != nil {
		return -1, -1
	}
	return d.U, d.RT
}

// TestUnansweredCountsOnlyWhatWeAsked pins the fact `rt` alone cannot carry. An old `rt` means either
// "nobody answered" or "I never asked", and only the sender can tell those apart — so a tunnel whose
// upstream is blackholed is indistinguishable from one that has simply been quiet, from that end. The
// counter moves ONLY when a keepalive really goes out, so any non-zero value is unanswered, full stop.
func TestUnansweredCountsOnlyWhatWeAsked(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "uasrv")
	cliDev, _ := tunPair(t, "uacli")
	addr := freeUDPPort(t)
	status := filepath.Join(t.TempDir(), "cli.status")

	// The session must ESTABLISH first: a client with no peer at all never gets past the handshake and
	// so never sends a keepalive. The state worth catching is a LIVE session whose answers stop — which
	// is exactly what a blackholed upstream looks like from this end.
	srv, err := Listen([]string{addr}, srvDev, 200*time.Millisecond, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, 200*time.Millisecond, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(status)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, rt := readUnans(status); rt > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, rt := readUnans(status); rt == 0 {
		t.Fatal("the tunnel never came up, so there is no live session to take the answers away from")
	}
	srv.Close() // the peer goes silent; the session lives on until it ages out

	deadline = time.Now().Add(10 * time.Second)
	var u int64
	for time.Now().Before(deadline) {
		if u, _ = readUnans(status); u >= 3 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the peer stopped answering and the count reached only %d — this is the ONE signal a single "+
		"end has that what it SENDS is not arriving, and it never moved", u)
}

// TestUnansweredClearsOnAnAnswer is the other half: on a live tunnel it must sit at zero, or the panel
// would condemn every healthy link.
func TestUnansweredClearsOnAnAnswer(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "ubsrv")
	cliDev, _ := tunPair(t, "ubcli")
	addr := freeUDPPort(t)
	status := filepath.Join(t.TempDir(), "cli.status")

	srv, err := Listen([]string{addr}, srvDev, 200*time.Millisecond, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, 200*time.Millisecond, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(status)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if u, rt := readUnans(status); rt > 0 && u == 0 {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	u, rt := readUnans(status)
	t.Fatalf("on a LIVE tunnel the count settled at %d with rt=%d — an answered keepalive must clear it, "+
		"or every healthy link reads as broken", u, rt)
}
