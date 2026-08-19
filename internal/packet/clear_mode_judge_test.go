package packet

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func clearModePair(t *testing.T, tag string) (*UDP, *UDP) {
	t.Helper()
	srvDev, _ := tunPair(t, tag+"s")
	cliDev, _ := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()

	srv, err := Listen([]string{addr}, srvDev, false, false, "", "", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, false, false, "", "", false, 0, 0)
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

func ready(cli *UDP) bool {
	_, _, r := cli.st.tracker.snapshot()
	return r
}

func TestAClearModeTunnelKeepsItsJudgeWhenItGoesSilent(t *testing.T) {
	cli, srv := clearModePair(t, "cmj")

	up := time.Now().Add(10 * time.Second)
	for !ready(cli) {
		if time.Now().After(up) {
			t.Fatal("a carrying clear-mode tunnel never published ready — the node would never judge it")
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !ready(cli) {
			t.Fatalf("ready went false %v into the silence — the node stops sending verdicts there, "+
				"which leaves this tunnel with no ladder at all",
				time.Until(deadline).Round(time.Millisecond))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAClearModeTunnelWritesNoStaleEvent(t *testing.T) {
	cli, srv := clearModePair(t, "cms")
	path := cli.st.path
	srv.Close()
	time.Sleep(3 * time.Second)

	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "stale" {
			t.Fatalf("core still writes a %q event: %+v", "stale", e)
		}
	}
}
