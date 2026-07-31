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
// destination pool, reproducing the exact sequence an operator hits: the rotation timer has already
// built and parked the NEXT carrier when the pin arrives.
//
// buildWarm resolves its target through dialCarrier -> dialTarget -> pp.current() at BUILD time, i.e.
// before the pin exists, and the adoption path reuses that connection verbatim without re-consulting
// the pool. So the tunnel came up on the ROTATION's endpoint, published it as active, logged a
// peer-rotate naming it — and then called pinLanded(), which cleared the pin unconditionally. The panel
// reported the operator's jump as complete while the tunnel sat on a different IP, with nothing in the
// log mentioning the pin. "I pinned #3 and it went to #2."
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
	pool := NewPeerPool([]string{a1, a2}, false, 0, "")
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

// TestWSPoolPinMatches covers the read-only pin check the warm-standby loop consults before letting a
// freshly dialed carrier become the ACTIVE. A background active dial started before the pin resolves
// its edge through current() at dial time, so its result can be for the pre-pin edge; adopting it left
// the operator on an edge they did not pick AND — because it did not match — pinApplied never cleared
// the pin, so proactive rotation stayed frozen for the rest of pinTTL.
func TestWSPoolPinMatches(t *testing.T) {
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis("front-a", "front-b"), true, "")

	// No pin in force: every carrier is adoptable.
	if !p.pinMatches("1.1.1.1", "front-a") || !p.pinMatches("2.2.2.2", "front-b") {
		t.Fatal("with no pin in force every edge must be adoptable")
	}

	// An IP pin: only that IP matches, whatever the SNI.
	p.selectEntry("ip", "2.2.2.2")
	if p.pinMatches("1.1.1.1", "front-a") {
		t.Fatal("a carrier on the pre-pin IP must NOT be adoptable while an IP pin is in force")
	}
	if !p.pinMatches("2.2.2.2", "front-a") {
		t.Fatal("a carrier on the pinned IP must be adoptable")
	}

	// An SNI pin behaves the same on its own axis.
	p2 := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis("front-a", "front-b"), true, "")
	p2.selectEntry("sni", "front-b")
	if p2.pinMatches("1.1.1.1", "front-a") {
		t.Fatal("a carrier on the pre-pin SNI must NOT be adoptable while an SNI pin is in force")
	}
	if !p2.pinMatches("1.1.1.1", "front-b") {
		t.Fatal("a carrier on the pinned SNI must be adoptable")
	}
}
