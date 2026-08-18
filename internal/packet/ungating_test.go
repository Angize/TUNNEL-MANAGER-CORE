package packet

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// poollessClient brings up a REAL udp client/server pair with no rotation pool of any kind — the shape
// every tunnel has when the operator picked one destination and one source, which is most of them. Only
// the status file is wired, because that is what the verdict mailbox hangs off. It returns once the peer
// has answered, so a test that then asserts something about a live tunnel really has one.
//
// The server comes back too, for the tests that need it to stop answering.
func poollessClient(t *testing.T, ka time.Duration, tag string) (cli, server *UDP, ctrl *os.File) {
	t.Helper()
	srvDev, _ := tunPair(t, tag+"s")
	cliDev, cc := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", c.LocalAddr().(*net.UDPAddr).Port)
	c.Close()
	srv, err := Listen([]string{addr}, srvDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err = Dial(addr, cliDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetStatusPath(filepath.Join(t.TempDir(), "core.json"))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for !cli.peerAnswered.Load() {
		if _, err := cc.Write(make([]byte, 120)); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cli, srv, cc
}

// TestAPoolLessTunnelHearsTheJudge is the class, driven end to end through Run(): a client with no pool
// used to start no verdict poller at all, so the node's measurement — the only thing that knows whether
// this tunnel CARRIES — reached it never. Its one way back from a peer that restarted was the staleness
// clock, minutes of dead tunnel for something one round trip settles.
//
// The keepalive here sizes that clock at deadWindow(ka), far past the budget below, so a re-handshake
// inside it is the verdict's doing and cannot be the clock's.
func TestAPoolLessTunnelHearsTheJudge(t *testing.T) {
	const ka = 6 * time.Second
	const budget = 4 * time.Second
	cli, _, _ := poollessClient(t, ka, "ungate")

	for cli.sealer() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	was := cli.session.Load()
	start := time.Now()
	liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail})

	deadline := time.Now().Add(deadWindow(ka) + 10*time.Second)
	for cli.session.Load() == was || cli.sealer() == nil {
		if time.Now().After(deadline) {
			t.Fatal("a tunnel with no pool never re-handshaked on the node's verdict — it has no ladder")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if took := time.Since(start); took > budget {
		t.Errorf("the re-handshake took %v, over the %v budget — that is the staleness clock (%v), "+
			"not the ladder", took.Round(time.Millisecond), budget, deadWindow(ka))
	}
}

// TestAPoolLessLadderSpendsItsStepsAndCondemnsNobody is the same tunnel at the controller, where the
// order is visible. Both free rungs are still spent, in cost order, and once they are gone the verdict
// is simply absorbed: there is no second endpoint, so nothing may be burned and nothing may move.
func TestAPoolLessLadderSpendsItsStepsAndCondemnsNobody(t *testing.T) {
	rc := newRotationController(nil, nil)
	rc.setVerdict(filepath.Join(t.TempDir(), "core.json.verdict"))
	rolls, drops, moves := 0, 0, 0
	rc.port.setRoll(func(bool) bool { rolls++; return true })
	rc.session.setDrop(func() bool { drops++; return true })
	rot := func(bool) { moves++ }

	fail := func() {
		liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdFail})
		rc.pollPins(func() {}, func() {}, rot, rot, nil, atPathEpoch)
	}

	for i := 1; i <= portTries; i++ {
		fail()
		if drops != 0 {
			t.Fatalf("verdict %d: the redraws must be spent before the handshake", i)
		}
	}
	fail()
	if drops != 1 {
		t.Errorf("with the redraws spent the next verdict must handshake again, got %d", drops)
	}
	for i := 0; i < 3; i++ {
		fail()
	}
	if rolls != portTries || drops != 1 {
		t.Errorf("the ladder kept spending past its budget: rolls=%d drops=%d", rolls, drops)
	}
	if moves != 0 {
		t.Errorf("a tunnel with no pool moved %d times — there is nowhere to move to", moves)
	}

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdOK})
	rc.pollPins(func() {}, func() {}, rot, rot, nil, atPathEpoch)
	fail()
	if rolls != portTries+1 {
		t.Errorf("traffic crossing did not refill the draws: %d, want %d", rolls, portTries+1)
	}
}

// TestASourcePooledTunnelHearsItsVerdict covers the shape where the operator picked several SOURCE IPs
// and one destination. There is no destination pool, so the verdict used to be written into a file that
// pool would have owned and nothing ever read it — the source walked blind, on nothing but the carrier's
// own frames coming back, which is exactly the evidence this whole design refuses.
func TestASourcePooledTunnelHearsItsVerdict(t *testing.T) {
	dir := t.TempDir()
	src := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "srcpool"))
	rc := newRotationController(nil, src)
	rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	noop := func() {}
	rotSrc := func(bool) { src.fail() }

	// The free steps come first and are spent one verdict at a time; stop at the round that reaches the
	// source, so the assertion is about the FIRST move and not about whatever the extra rounds did.
	rc.session.setDrop(func() bool { return true })
	burned, cur := false, ""
	for i := 0; i < portTries+4 && !burned; i++ {
		liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdFail})
		rc.pollPins(noop, noop, func(bool) {}, rotSrc, nil, atPathEpoch)
		src.mu.Lock()
		burned, cur = src.health.recs["s1"] != nil, src.addrs[src.cur]
		src.mu.Unlock()
	}
	if !burned {
		t.Fatal("with no destination pool the source is the only axis left, and the ask never reached it")
	}
	if cur != "s2" {
		t.Errorf("and it must move off the source it burned, got %q", cur)
	}
}

// TestAVerdictAndAPinAreSeparateMailboxes is what makes the whole class structurally impossible. They
// used to share one file, which is why the verdict could only reach a tunnel that owned a pool to hold
// it — and why the dispatch needed a guard against reading a fail as a pin. Two files, two questions:
// the judge's is about the PATH, the operator's is about a pool ENTRY, and one poll settles both.
func TestAVerdictAndAPinAreSeparateMailboxes(t *testing.T) {
	p, rc := judgedPool(t, "a", "b")
	pinned := 0

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdFail, Key: "a"})
	writeFileAtomic(p.cmdPath(), []byte(`{"key":"b"}`), 0o644)
	rc.pollPins(func() { pinned++ }, func() {}, func(bool) { p.fail() }, func(bool) {}, nil, atPathEpoch)

	if !burnedIn(p)["a"] {
		t.Error("the verdict did not burn the endpoint it named — the pin file swallowed it")
	}
	if pinned != 1 {
		t.Errorf("the pin was applied %d times, want once — the verdict consumed its file", pinned)
	}
	p.mu.Lock()
	pin := p.pinKey
	p.mu.Unlock()
	if pin != "b" {
		t.Errorf("the pool is pinned to %q, want b", pin)
	}
}
