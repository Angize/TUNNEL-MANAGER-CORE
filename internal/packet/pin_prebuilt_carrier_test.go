//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func liveRemote(b *TCP) string {
	if c := b.curConn.Load(); c != nil {
		return (*c).RemoteAddr().String()
	}
	return ""
}

func TestPinIsNotConsumedByAPreBuiltRotationCarrier(t *testing.T) {
	const psk = "pin-prebuilt-rotation-psk-abcdef"
	const cipher = "aes-256-gcm"

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1 := fmt.Sprintf("127.0.0.1:%d", port)
	a2 := fmt.Sprintf("127.0.0.2:%d", port)

	srvDev, _ := tunPair(t, "pinsrv")
	srv, err := ListenTCP([]string{a1, a2}, srvDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	cliDev, _ := tunPair(t, "pincli")
	cli, err := DialTCP(a1, cliDev, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	pool := NewPeerPool([]string{a1, a2}, 0, "")
	cli.SetPeerPool(pool)
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "the client came up on the first endpoint", func() bool {
		return liveRemote(cli) == a1
	})

	if !cli.buildWarm(func() {}, "", true, "") {
		t.Fatal("buildWarm did not park a carrier — the test cannot reproduce the race")
	}

	if !pool.selectEntry(a2) {
		t.Fatalf("selectEntry(%s) refused the pin", a2)
	}
	cli.manualSwitch.Store(true)
	if c := cli.curConn.Load(); c != nil {
		(*c).Close()
	}

	waitFor(t, 6*time.Second, "the tunnel landed on the PINNED endpoint", func() bool {
		return liveRemote(cli) == a2
	})

	waitFor(t, 4*time.Second, "the pin was released once it landed", func() bool {
		return !pool.isPinned()
	})
	if got := liveRemote(cli); got != a2 {
		t.Fatalf("tunnel is on %s after the pin was released, want the pinned %s", got, a2)
	}
}
