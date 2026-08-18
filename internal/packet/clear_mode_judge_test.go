package packet

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// clearModePair brings up a REAL udp client/server with crypto OFF — the one datagram configuration
// config.go still allows to run clear — and returns once the peer has answered, so `ready` is genuinely
// true before anything is asserted about it going false.
func clearModePair(t *testing.T, ka time.Duration, tag string) (*UDP, *UDP) {
	t.Helper()
	srvDev, _ := tunPair(t, tag+"s")
	cliDev, _ := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()

	srv, err := Listen([]string{addr}, srvDev, ka, false, false, "", "", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, ka, false, false, "", "", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.json"))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(15 * time.Second)
	for !cli.peerAnswered.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the clear-mode tunnel never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cli, srv
}

// ready is what the node gates every verdict on: it reads it out of the status file before AND after its
// probe and sends nothing unless both are set.
func ready(cli *UDP) bool {
	_, _, r := cli.st.tracker.snapshot()
	return r
}

// TestAClearModeTunnelKeepsItsJudgeWhenItGoesSilent is the behaviour change this PR is really about, and
// the reason it could not just be a deletion.
//
// In clear mode there is no session, so `ready` IS peerAnswered. The staleness branch cleared that flag
// on silence — which switched the node's verdicts off for exactly the tunnel that needed them, because
// the node sends none unless `ready` held across its probe. So a clear-mode tunnel that went quiet had
// no ladder at all, and the only thing that could ever heal it was the peer coming back on its own.
//
// With the branch gone the flag keeps meaning what it says — this endpoint HAS answered us — and the
// judge goes on measuring where the payload actually travels.
func TestAClearModeTunnelKeepsItsJudgeWhenItGoesSilent(t *testing.T) {
	const ka = 2 * time.Second // the window the deleted clock used would have been 3x this
	cli, srv := clearModePair(t, ka, "cmj")

	// The tracker samples on its own one-second beat, so wait for the publish rather than racing it.
	up := time.Now().Add(10 * time.Second)
	for !ready(cli) {
		if time.Now().After(up) {
			t.Fatal("a carrying clear-mode tunnel never published ready — the node would never judge it")
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv.Close() // the peer vanishes: nothing will answer another ping

	// Well past the window the staleness clock enforced. Sampled throughout, not just at the end: the
	// old branch fired repeatedly, so a single late read could miss a flag that was cleared and re-set.
	deadline := time.Now().Add(3 * deadWindow(ka))
	for time.Now().Before(deadline) {
		if !ready(cli) {
			t.Fatalf("ready went false %v into the silence — the node stops sending verdicts there, "+
				"which leaves this tunnel with no ladder at all",
				time.Until(deadline).Round(time.Millisecond))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAClearModeTunnelWritesNoStaleEvent: the `stale` code has no writer left anywhere in core. The
// panel's text for it said "re-handshaking", which clear mode never does — it has no session — so every
// time that line appeared it was wrong about the only thing it claimed.
func TestAClearModeTunnelWritesNoStaleEvent(t *testing.T) {
	const ka = 2 * time.Second
	cli, srv := clearModePair(t, ka, "cms")
	path := cli.st.path
	srv.Close()
	time.Sleep(3 * deadWindow(ka))

	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "stale" {
			t.Fatalf("core still writes a %q event: %+v", "stale", e)
		}
	}
}
