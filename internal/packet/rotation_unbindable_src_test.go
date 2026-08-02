//go:build linux

package packet

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUnbindableSourceRotationIsNotAnnounced closes the last corner of the announce-a-move-that-did-not-
// happen class: a timed rotation onto a source IP that is no longer on this host. dialer() installs
// LocalAddr only where the IP is bindable, so the socket leaves from the KERNEL DEFAULT while the connect
// and handshake succeed and the carrier IS adopted. The destination pool moves too, as a positive control.
func TestUnbindableSourceRotationIsNotAnnounced(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	const gone = "203.0.113.9" // TEST-NET-3: in the pool, never on the box
	srvDev, _ := tunPair(t, "ubsrv")
	cliDev, _ := tunPair(t, "ubcli")
	ka := time.Second

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	d1, d2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := ListenTCP([]string{d1, d2}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(d1, cliDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")
	// Both pools rotate on the same 1s beat: the destination really can move (two live endpoints),
	// the source cannot (the only alternative is not on this host).
	cli.SetPeerPool(NewPeerPool([]string{d1, d2}, true, time.Second, ""))
	cli.SetSourcePool(NewPeerPool([]string{"127.0.0.1", gone}, true, time.Second, ""))
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	// Wait for the positive control: a peer-rotate proves a warm carrier was built AND adopted, i.e.
	// the very block that decides the src-rotate ran.
	deadline := time.Now().Add(25 * time.Second)
	var events []coreEvent
	adopted := false
	for time.Now().Before(deadline) && !adopted {
		if _, err := os.Stat(statusPath); err == nil {
			events = coreStatusEvents(t, statusPath)
			for _, e := range events {
				if e.Code == "peer-rotate" {
					adopted = true
					break
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !adopted {
		t.Fatalf("no warm carrier was adopted within the budget, so this test proves nothing; events=%+v", events)
	}

	for _, e := range events {
		if e.Code == "src-rotate" && strings.Contains(e.Detail, gone) {
			t.Fatalf("the adoption site announced src-rotate for %s — an IP that is not on this host, so "+
				"dialer() installed no LocalAddr and the socket left from the kernel default. The panel "+
				"would show the tunnel sourced from an address it never sent a packet from; events=%+v",
				gone, events)
		}
	}
}
