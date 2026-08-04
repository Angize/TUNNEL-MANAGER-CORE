package packet

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const probePSK = "probe-shared-pre-shared-key-1234567890"

// probePair brings up a REAL udp client/server pair bound on two loopback IPs at one port, with a
// destination rotation pool on the client (a1, a2, then any extra entries). The client dials a1, so
// everything past it is an endpoint the LIVE carrier is never on — which is exactly what the
// out-of-band prober is for. It returns only once the peer has answered, so a test that then asserts
// "the carrier did not move" is talking about a carrier that was moving.
func probePair(t *testing.T, ka time.Duration, tag string, extra ...string) (cli, srv *UDP, a1, a2 string, cliCtrl, srvCtrl *os.File) {
	t.Helper()
	srvDev, sc := tunPair(t, tag+"s")
	cliDev, cc := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1 = fmt.Sprintf("127.0.0.1:%d", port)
	a2 = fmt.Sprintf("127.0.0.2:%d", port)
	srv, err = Listen([]string{a1, a2}, srvDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err = Dial(a1, cliDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dir := t.TempDir()
	cli.SetStatusPath(filepath.Join(dir, "core.json"))
	cli.SetPeerPool(NewPeerPool(append([]string{a1, a2}, extra...), true, 0, filepath.Join(dir, "pool.json")))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	pkt := bytes.Repeat([]byte{0xC7}, 120)
	deadline := time.Now().Add(10 * time.Second)
	for !cli.peerAnswered.Load() {
		if _, err := cc.Write(pkt); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cli, srv, a1, a2, cc, sc
}

// burnEntry burns one pool entry through the pool's own methods only: walk the cursor onto it, fail it
// (which burns it and advances off it), and confirm it really is suspect. Only the pool's cursor moves
// — the carrier's peer is driven by rotatePeerUDP, which nothing here calls.
func burnEntry(t *testing.T, p *PeerPool, target string) {
	t.Helper()
	for i := 0; p.current() != target; i++ {
		if i >= p.size() {
			t.Fatalf("could not walk the cursor onto %s", target)
		}
		if _, moved := p.rotateOnce(); !moved {
			t.Fatalf("rotateOnce did not move while walking onto %s", target)
		}
	}
	p.fail()
	p.mu.Lock()
	r := p.health[target]
	p.mu.Unlock()
	if r == nil || r.state != stateSuspect {
		t.Fatalf("%s should be suspect after fail(), got %+v", target, r)
	}
	if got := p.current(); got == target {
		t.Fatalf("fail() should have advanced off %s", target)
	}
}

// waitHealthy polls until addr has no health record left, or gives up.
func waitHealthy(p *PeerPool, addr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		r := p.health[addr]
		p.mu.Unlock()
		if r == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestDestProbeHealsWithoutMovingTheCarrier is the whole point of the prober, driven end to end over
// real sockets: a burned endpoint the tunnel is NOT on is re-admitted by a handshake it answers on its
// own, while the live carrier keeps its peer, its session and its data flow. Before this, the only way
// to retest that endpoint was to point the live data plane at it and watch.
func TestDestProbeHealsWithoutMovingTheCarrier(t *testing.T) {
	cli, _, a1, a2, cc, sc := probePair(t, time.Second, "dph")
	burnEntry(t, cli.pp, a2)
	sessBefore := cli.session.Load()
	if sessBefore == nil {
		t.Fatal("crypto tunnel has no session")
	}
	cli.pp.probeAllNow() // the "probe now" control: a2's retest is due right away
	if !waitHealthy(cli.pp, a2, 20*time.Second) {
		t.Fatalf("the prober did not re-admit %s", a2)
	}
	if got := cli.peer.Load().String(); got != a1 {
		t.Fatalf("the live carrier moved: peer %s, want %s", got, a1)
	}
	if cli.session.Load() != sessBefore {
		t.Fatal("the probe replaced the live session — its RESP must install nothing")
	}
	if cli.ci.Load() != nil {
		t.Fatal("the probe left a handshake ephemeral on the live carrier")
	}
	pkt := bytes.Repeat([]byte{0x3E}, 300)
	if _, err := cc.Write(pkt); err != nil {
		t.Fatalf("inject after probe: %v", err)
	}
	if got := readWithTimeout(t, sc, "client->server after probe"); !bytes.Equal(got, pkt) {
		t.Fatalf("the tunnel stopped carrying after the probe: got %d bytes", len(got))
	}
}

// TestDestProbeUnansweredStepsTheBackoff is the other half: an endpoint that answers nothing is NOT
// re-admitted, and the failed probe walks it one step further down the retest ladder. The endpoint is a
// loopback address with no listener, which gives the probe exactly what a blocked IP gives — silence.
func TestDestProbeUnansweredStepsTheBackoff(t *testing.T) {
	dead := "127.0.0.9:9"
	cli, _, _, _, _, _ := probePair(t, time.Second, "dpu", dead)
	p := cli.pp
	burnEntry(t, p, dead)
	p.probeAllNow()
	deadline := time.Now().Add(40 * time.Second)
	for {
		p.mu.Lock()
		r := p.health[dead]
		fails, state, next := 0, "", int64(0)
		if r != nil {
			fails, state, next = r.fails, r.state, r.nextRetest
		}
		p.mu.Unlock()
		if r == nil {
			t.Fatal("an unanswered probe must not re-admit the endpoint")
		}
		if fails > 0 {
			if state != stateSuspect && state != stateDead {
				t.Fatalf("%s should still be burned, got %q", dead, state)
			}
			if next <= p.now() {
				t.Fatalf("a failed probe should push the next retest out, got %d <= %d", next, p.now())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a probe of an endpoint that answers nothing never stepped the backoff")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDueRetestsSkipsTheActiveEndpoint locks in which endpoints the prober is handed. The active one is
// left out on purpose: it is the live carrier's, its verdict belongs to the node's tun probe, and its
// answer cannot be told apart from the traffic already crossing it.
func TestDueRetestsSkipsTheActiveEndpoint(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b", "c"}, true, 0, "")
	p.now = func() int64 { return clk }
	p.fail() // burn a, cursor moves off it
	if due := p.dueRetests(); len(due) != 0 {
		t.Fatalf("nothing is due yet, got %v", due)
	}
	clk += suspectBackoff[0]
	if due := p.dueRetests(); len(due) != 1 || due[0] != "a" {
		t.Fatalf("a should be due, got %v", due)
	}
	// Put the cursor back on the burned endpoint: it is the live one now, so it drops out.
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	if due := p.dueRetests(); len(due) != 0 {
		t.Fatalf("the active endpoint must not be probed, got %v", due)
	}
}

// TestRetestResultDrivesTheFSM checks the verdict half on its own: a success re-admits and reports the
// heal exactly once, a failure walks the backoff, and a verdict for an endpoint something else already
// cleared reports nothing — so no duplicate heal event reaches the panel log.
func TestRetestResultDrivesTheFSM(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	p.fail() // a is suspect, fails=0
	if p.retestResult("a", false) {
		t.Fatal("a failed retest is not a heal")
	}
	p.mu.Lock()
	r := p.health["a"]
	fails, next := r.fails, r.nextRetest
	p.mu.Unlock()
	if fails != 1 || next != clk+suspectBackoff[1] {
		t.Fatalf("a failed retest should step to fails=1 at +%ds, got fails=%d next=+%d", suspectBackoff[1], fails, next-clk)
	}
	if !p.retestResult("a", true) {
		t.Fatal("an answered retest must report the heal")
	}
	p.mu.Lock()
	healed := p.health["a"] == nil
	p.mu.Unlock()
	if !healed {
		t.Fatal("an answered retest must re-admit the endpoint")
	}
	if p.retestResult("a", true) {
		t.Fatal("a verdict for an already-healthy endpoint must report nothing")
	}
}
