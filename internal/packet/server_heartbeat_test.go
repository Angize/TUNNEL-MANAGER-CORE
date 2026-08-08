package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// hbKeepalive sizes both the ping rate and the dead window (deadMult x keepalive). dw is published in
// whole SECONDS, so a sub-second window would round to 0 and this test's dw assertion would be asserting
// nothing — the window has to stay at least a second wide.
const hbKeepalive = time.Second

// readHB pulls hb, dw and role out of a status file.
func readHB(path string) (hb, dw int64, role string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, ""
	}
	var d struct {
		HB   int64  `json:"hb"`
		DW   int64  `json:"dw"`
		Role string `json:"role"`
	}
	if json.Unmarshal(b, &d) != nil {
		return 0, 0, ""
	}
	return d.HB, d.DW, d.Role
}

// TestServerPublishesItsOwnHeartbeat drives a real tunnel and asserts BOTH ends publish. The server's
// lastRx proves the CLIENT->SERVER direction, which is a fact only that end can observe — and it was
// already being tracked in memory and simply never written, so the server end had no liveness signal
// and every reader fell back to probing it with ICMP.
func TestServerPublishesItsOwnHeartbeat(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "shsrv")
	cliDev, _ := tunPair(t, "shcli")
	addr := freeUDPPort(t)
	dir := t.TempDir()
	srvStatus := filepath.Join(dir, "srv.status")
	cliStatus := filepath.Join(dir, "cli.status")

	srv, err := Listen([]string{addr}, srvDev, hbKeepalive, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, hbKeepalive, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	srv.SetStatusPath(srvStatus)
	cli.SetStatusPath(cliStatus)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(8 * time.Second)
	var shb, sdw int64
	var srole string
	for time.Now().Before(deadline) {
		if shb, sdw, srole = readHB(srvStatus); shb > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if shb == 0 {
		t.Fatal("the SERVER published no heartbeat — it tracks lastRx on every authenticated frame, so " +
			"withholding it leaves that end with no liveness signal at all")
	}
	if sdw == 0 {
		t.Fatal("the server published no dead-window, so a reader cannot age its heartbeat")
	}
	if srole != "server" {
		t.Fatalf("role = %q, want \"server\" — a reader must be able to tell a server WAITING for its "+
			"first client from a client that went quiet", srole)
	}
	// WAIT for the client too. The two ends publish on their own timers, so the server's first heartbeat
	// says nothing about whether the client has stamped one yet — reading it once asserted an ordering
	// nothing establishes. Its OWN deadline: the loop above may have spent most of the shared one.
	var chb int64
	var crole string
	cliDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(cliDeadline) {
		if chb, _, crole = readHB(cliStatus); chb > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if chb == 0 || crole != "client" {
		t.Fatalf("the client end regressed: hb=%d role=%q", chb, crole)
	}
}

// TestServerHeartbeatAdvances pins that it keeps moving: one stamp at connect would be indistinguishable
// from a server that later stopped being reached, which is the state this exists to expose.
func TestServerHeartbeatAdvances(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "sasrv")
	cliDev, _ := tunPair(t, "sacli")
	addr := freeUDPPort(t)
	status := filepath.Join(t.TempDir(), "srv.status")

	srv, err := Listen([]string{addr}, srvDev, hbKeepalive, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, hbKeepalive, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	srv.SetStatusPath(status)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	var first int64
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if first, _, _ = readHB(status); first > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if first == 0 {
		t.Fatal("no server heartbeat to watch")
	}
	deadline = time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if hb, _, _ := readHB(status); hb > first {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("the server heartbeat froze at %d — it must advance while the client keeps reaching it", first)
}
