//go:build linux

package packet

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// liveRemote returns the address the client's live carrier is actually connected to ("" if none).
func liveRemote(b *TCP) string {
	if c := b.curConn.Load(); c != nil {
		return (*c).RemoteAddr().String()
	}
	return ""
}

// TestPinIsNotConsumedByAPreBuiltRotationCarrier drives the real dialLoop of a direct-TCP client with a
// destination pool, reproducing the sequence an operator hits: the rotation timer has already built and
// parked the NEXT carrier when the pin arrives. buildWarm resolved its target BEFORE the pin existed and
// the adoption path reuses that connection verbatim, so the pin must not be released against it.
func TestPinIsNotConsumedByAPreBuiltRotationCarrier(t *testing.T) {
	const psk = "pin-prebuilt-rotation-psk-abcdef"
	const cipher = "aes-256-gcm"
	ka := time.Second

	// One core server bound to two loopback addresses on the same port, so the endpoint the client
	// landed on is visible from the outside as the carrier's remote address.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1 := fmt.Sprintf("127.0.0.1:%d", port)
	a2 := fmt.Sprintf("127.0.0.2:%d", port)

	srvDev, _ := tunPair(t, "pinsrv")
	srv, err := ListenTCP([]string{a1, a2}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	cliDev, _ := tunPair(t, "pincli")
	cli, err := DialTCP(a1, cliDev, ka, false, true, psk, cipher, false, "")
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

	// The rotation timer parks the NEXT carrier. It resolves pp.current() now — a1 — which is the whole
	// point of make-before-break, and the whole reason a later pin can be ignored.
	if !cli.buildWarm(func() {}, "", true, "") {
		t.Fatal("buildWarm did not park a carrier — the test cannot reproduce the race")
	}

	// NOW the operator pins the other endpoint. These are exactly the two steps peerPinPollLoop takes:
	// force the pool onto the pick, then drop the live carrier so dialLoop re-dials.
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
	// ...and only then is the pin released, because it actually landed.
	waitFor(t, 4*time.Second, "the pin was released once it landed", func() bool {
		return !pool.isPinned()
	})
	if got := liveRemote(cli); got != a2 {
		t.Fatalf("tunnel is on %s after the pin was released, want the pinned %s", got, a2)
	}
}
