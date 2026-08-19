package packet

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func sourcedPair(t *testing.T, tag string) (cli *UDP, dst, src *PeerPool) {
	t.Helper()
	srvDev, _ := tunPair(t, tag+"s")
	cliDev, _ := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1 := fmt.Sprintf("127.0.0.1:%d", port)
	a2 := fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := Listen([]string{a1, a2}, srvDev, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err = Dial(a1, cliDev, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dir := t.TempDir()
	cli.SetStatusPath(filepath.Join(dir, "core.json"))
	dst = NewPeerPool([]string{a1, a2}, 0, filepath.Join(dir, "peerpool"))
	src = NewPeerPool([]string{"127.0.0.1", "127.0.0.2"}, 0, filepath.Join(dir, "srcpool"))
	cli.SetPeerPool(dst)
	cli.SetSourcePool(src)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(15 * time.Second)
	for !cli.peerAnswered.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cli, dst, src
}

func TestAPacketArrivingIsNotTheJudgeSayingItCarries(t *testing.T) {
	cli, dst, src := sourcedPair(t, "srcaxis")

	was := activeOf(src)
	burned, srcMoved := false, false
	for i := 0; i < 5 && !(burned && srcMoved); i++ {
		liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail, Key: activeOf(dst)})
		time.Sleep(3 * time.Second)
		burned = burned || len(burnedIn(dst)) > 0
		srcMoved = srcMoved || activeOf(src) != was
	}
	if !burned {
		t.Errorf("five verdicts and no destination was ever condemned. The carrier is receiving the "+
			"whole time, and a packet arriving refilled the free rungs on every keepalive beat, so the "+
			"ladder spent a step it had not earned and never reached the walk. Only the judge saying "+
			"the tunnel CARRIES may refill them; still burned: %v", burnedIn(dst))
	}
	if !srcMoved {
		t.Errorf("the destination pool was walked and the source never left %s", was)
	}
}

func TestTheTimedRotationRunsWhileThereIsNoSession(t *testing.T) {
	cliDev, _ := tunPair(t, "protc")
	cli, err := Dial("127.0.0.1:9", cliDev, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dst := NewPeerPool([]string{"127.0.0.1:9", "127.0.0.2:9"}, time.Second, "")
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.json"))
	cli.SetPeerPool(dst)
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	was := activeOf(dst)
	deadline := time.Now().Add(15 * time.Second)
	for activeOf(dst) == was {
		if cli.sealer() != nil {
			t.Fatal("setup: something answered on the discard port, so this is not an outage")
		}
		if time.Now().After(deadline) {
			t.Fatalf("the operator's rotation timer never fired in 15s of outage with a 1s period. "+
				"It only runs on the beats that already have a session, which is every beat except "+
				"the ones an outage is made of. Still on %s", was)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
