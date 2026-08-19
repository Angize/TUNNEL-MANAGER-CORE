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

func TestRotateSourceTCPProactiveDefersEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "src.status")
	b := &TCP{isClient: true, stTag: "tcp", addr: "d0:443"}
	b.st = newCoreStatus(path, "tcp · d0:443")
	b.SetSourcePool(NewPeerPool([]string{"10.0.0.5", "10.0.0.6"}, 0, ""))

	addr, moved := b.rotateSourceTCP(true)
	if !moved || addr != "10.0.0.6" {
		t.Fatalf("proactive rotate: addr=%q moved=%v, want 10.0.0.6/true", addr, moved)
	}
	if ev := coreStatusEvents(t, path); len(ev) != 0 {
		t.Fatalf("a proactive source rotation published %d event(s); it must defer to the adoption site: %+v", len(ev), ev)
	}

	if _, moved := b.rotateSourceTCP(false); !moved {
		t.Fatal("failover rotate should move in a 2-entry pool")
	}
	ev := coreStatusEvents(t, path)
	if len(ev) != 1 || ev[0].Kind != "down" || ev[0].Code != "src-rotate" {
		t.Fatalf("failover source rotation: events=%+v, want exactly one down/src-rotate", ev)
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

	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, 0, ""))
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

	cli.SetPeerPool(NewPeerPool([]string{addr}, 0, ""))
	cli.SetSourcePool(NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, time.Second, ""))
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
