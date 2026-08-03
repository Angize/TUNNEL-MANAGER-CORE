//go:build linux

package packet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// coreStatusEvents reads a coreStatus file and returns its event ring.
func coreStatusEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status %s: %v", path, err)
	}
	var doc struct {
		Active string      `json:"active"`
		Events []coreEvent `json:"events"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return doc.Events
}

// TestRotateSourceTCPProactiveDefersEvent pins the contract at the point that decides publication: a
// PROACTIVE source rotation advances the pool but announces NOTHING — the move is not real until the
// warm carrier goes live at the adoption site — while a FAILOVER rotation, the tunnel really leaving a
// dead source, is announced at once. Announcing proactively describes a move a failed build never made.
func TestRotateSourceTCPProactiveDefersEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "src.status")
	b := &TCP{isClient: true, stTag: "tcp", addr: "d0:443"}
	b.st = newCoreStatus(path, "tcp · d0:443", "client")
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, true, 0, ""))

	addr, moved := b.rotateSourceTCP(true) // proactive beat
	if !moved || addr != "10.0.0.6" {
		t.Fatalf("proactive rotate: addr=%q moved=%v, want 10.0.0.6/true", addr, moved)
	}
	if ev := coreStatusEvents(t, path); len(ev) != 0 {
		t.Fatalf("a proactive source rotation published %d event(s); it must defer to the adoption site: %+v", len(ev), ev)
	}

	if _, moved := b.rotateSourceTCP(false); !moved { // failover beat
		t.Fatal("failover rotate should move in a 2-entry pool")
	}
	ev := coreStatusEvents(t, path)
	if len(ev) != 1 || ev[0].Kind != "down" || ev[0].Code != "src-rotate" {
		t.Fatalf("failover source rotation: events=%+v, want exactly one down/src-rotate", ev)
	}
}

// TestDirectPoolShortDeathEmitsOneDown: a genuine, sub-minLiveness death on a direct destination pool
// must surface EXACTLY ONE 'down' event — the classified reason — not a "peer-rotate" down from the burn
// plus the classified one, which leaves the operator reading twice as many disconnects as happened. It
// stands up a real server on two loopback IPs and drops the client's live connection directly.
func TestDirectPoolShortDeathEmitsOneDown(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "pdsrv")
	cliDev, cliCtrl := tunPair(t, "pdcli")
	ka := 1 * time.Second

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := ListenTCP([]string{a1, a2}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(a1, cliDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")
	// Direct dest pool (failover-only) + the coreStatus event ring under test.
	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, true, 0, ""))
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	// Wait until the client has a live connection published (curConn is stored right before serve()), so
	// dropping it takes the post-serve death path, then confirm data actually flows over it.
	deadline := time.Now().Add(10 * time.Second)
	for cli.curConn.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("client never established a live connection to the server")
		}
		time.Sleep(20 * time.Millisecond)
	}
	pkt := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}

	// Drop the live connection directly — a genuine death, well within minLiveness.
	cc := cli.curConn.Load()
	if cc == nil {
		t.Fatal("live connection vanished before the drop")
	}
	(*cc).Close()

	// Wait for the reconnect 'up' — by then every event for the drop is on disk.
	deadline = time.Now().Add(15 * time.Second)
	var events []coreEvent
	for time.Now().Before(deadline) {
		events = coreStatusEvents(t, statusPath)
		if hasKind(events, "up") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasKind(events, "up") {
		t.Fatalf("client never reconnected after the drop; events=%+v", events)
	}

	downs := 0
	var firstDown coreEvent
	for _, e := range events {
		if e.Kind == "down" {
			if downs == 0 {
				firstDown = e
			}
			downs++
		}
	}
	if downs != 1 {
		t.Fatalf("a single short death produced %d 'down' events, want exactly 1: %+v", downs, events)
	}
	if firstDown.Code == "peer-rotate" {
		t.Fatalf("the drop's down was logged as %q (a burn artefact); it must be the classified reason", firstDown.Code)
	}
}

func hasKind(events []coreEvent, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// TestSourceOnlyRotationDoesNotAnnounceTheDestination drives the REAL dialLoop: a timed rotation whose
// SOURCE pool moved while the destination pool could not must publish `src-rotate` only. The beat fires
// when EITHER pool advances, so gating the destination announcement on `b.pp != nil` alone names an
// endpoint the tunnel never left — the steady state once the other destinations are burned.
func TestSourceOnlyRotationDoesNotAnnounceTheDestination(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "sorsrv")
	cliDev, _ := tunPair(t, "sorcli")
	ka := time.Second

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := ListenTCP([]string{addr}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(addr, cliDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")
	// One destination (cannot rotate) + two bindable sources on a 1s beat (will rotate).
	cli.SetPeerPool(NewPeerPool([]string{addr}, true, 0, ""))
	cli.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, true, time.Second, ""))
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	// Wait for a source rotation to be adopted (the beat is 1s; give it room on a loaded box).
	deadline := time.Now().Add(20 * time.Second)
	var events []coreEvent
	for time.Now().Before(deadline) {
		if _, err := os.Stat(statusPath); err == nil {
			events = coreStatusEvents(t, statusPath)
			for _, e := range events {
				if e.Code == "src-rotate" {
					deadline = time.Time{} // got one
					break
				}
			}
		}
		if deadline.IsZero() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !deadline.IsZero() {
		t.Fatalf("no source rotation was adopted within the budget; events=%+v", events)
	}

	for _, e := range events {
		if e.Code == "peer-rotate" {
			t.Fatalf("a source-only rotation announced a DESTINATION rotation (%q/%q) — the tunnel never "+
				"left that endpoint; events=%+v", e.Code, e.Detail, events)
		}
	}
}
