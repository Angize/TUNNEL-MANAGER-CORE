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

// Both kinds of source rotation are announced, from the ONE site that performs them, and the two are
// told apart by whether they arm the recovery. They were not: the rotator announced only the failover
// and the rotation timer announced only the scheduled move, and both passed `true`, so a forced move
// read as a scheduled one and the "up" that should follow it was never armed.
func TestASourceRotationSaysWhichKindItWas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "src.status")
	b := &TCP{isClient: true, stTag: "tcp", addr: "d0:443"}
	b.SetStatusPath(path)
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0))

	addr, moved := b.rotateSourceTCP(true)
	if !moved || addr != "10.0.0.6" {
		t.Fatalf("proactive rotate: addr=%q moved=%v, want 10.0.0.6/true", addr, moved)
	}
	ev := coreStatusEvents(t, path)
	if len(ev) != 1 || ev[0].Code != "src-rotate" || ev[0].Detail != "ip:10.0.0.6" {
		t.Fatalf("a scheduled source rotation must be announced once: %+v", ev)
	}
	// A scheduled move is not an outage, so it must not arm the "up" that reports a recovery.
	b.st.reconnected("d0:443")
	if ev := coreStatusEvents(t, path); len(ev) != 1 {
		t.Fatalf("a scheduled rotation armed a recovery report: %+v", ev)
	}

	if _, moved := b.rotateSourceTCP(false); !moved {
		t.Fatal("failover rotate should move in a 2-entry pool")
	}
	// Three now: the pool announces the burn it just made, the carrier announces the rotation it
	// caused, and the rotation is marked as a failover, so the reconnect reports the recovery.
	ev = coreStatusEvents(t, path)
	if len(ev) != 3 {
		t.Fatalf("failover source rotation: events=%+v, want a burn and a src-rotate", ev)
	}
	if ev[1].Kind != "burn" || ev[1].Detail != "src:10.0.0.6" {
		t.Fatalf("second event should be the pool naming what IT burned, got %+v", ev[1])
	}
	if ev[2].Kind != "down" || ev[2].Code != "src-rotate" {
		t.Fatalf("third event should be the rotation, got %+v", ev[2])
	}
	b.st.reconnected("d0:443")
	ev = coreStatusEvents(t, path)
	if len(ev) != 4 || ev[3].Kind != "up" {
		t.Fatalf("a forced rotation must arm the report that the tunnel came back: %+v", ev)
	}
}

func TestDirectPoolShortDeathEmitsOneDown(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "pdsrv")
	cliDev, cliCtrl := tunPair(t, "pdcli")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := ListenTCP([]string{a1, a2}, srvDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(a1, cliDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")

	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, 0))
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

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

	cc := cli.curConn.Load()
	if cc == nil {
		t.Fatal("live connection vanished before the drop")
	}
	(*cc).Close()

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

func TestSourceOnlyRotationDoesNotAnnounceTheDestination(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "sorsrv")
	cliDev, _ := tunPair(t, "sorcli")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	srv, err := ListenTCP([]string{addr}, srvDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(addr, cliDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")

	cli.SetPeerPool(NewPeerPool([]string{addr}, 0))
	cli.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, time.Second))
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(20 * time.Second)
	var events []coreEvent
	for time.Now().Before(deadline) {
		if _, err := os.Stat(statusPath); err == nil {
			events = coreStatusEvents(t, statusPath)
			for _, e := range events {
				if e.Code == "src-rotate" {
					deadline = time.Time{}
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
