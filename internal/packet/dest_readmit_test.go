package packet

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// nodeBurn burns the pool's ACTIVE endpoint the way the node's fail command does — the burn plus the
// mark that says which measurement decided it — and returns the endpoint that was condemned.
func nodeBurn(p *PeerPool) string {
	gone := p.current()
	p.fail()
	p.markNodeBurn(gone)
	return gone
}

// TestCondemnedEndpointIsNotProbedAndNotHealed is the whole rule in one place. An endpoint the node's
// tun probe condemned is not handed to the prober at all, is not cleared by a live success, and is not
// eligible for a timed rotation. The reason is measured: an endpoint can answer a real PSK handshake
// while carrying nothing, so letting the handshake re-admit it puts the tunnel back on a dead IP.
func TestCondemnedEndpointIsNotProbedAndNotHealed(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	gone := nodeBurn(p) // burns "a" and marks it as the node's call; the cursor moves to "b"
	if gone != "a" {
		t.Fatalf("setup: expected to condemn a, got %s", gone)
	}
	clk += suspectBackoff[0] // its retest is now due

	if due := p.dueRetests(); len(due) != 0 {
		t.Fatalf("a condemned endpoint must not be handed to the prober, got %v", due)
	}
	if _, moved := p.rotateOnce(); moved {
		t.Fatal("the timed rotation must not move onto a condemned endpoint")
	}
	// A live success while the cursor sits on it — the exact shape that used to wipe the burn one
	// second after every rotation.
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	if healed := p.succeeded(); healed != "" {
		t.Fatalf("a returning frame re-admitted the condemned %s", healed)
	}
	p.mu.Lock()
	stillBurned := p.health["a"] != nil
	p.mu.Unlock()
	if !stillBurned {
		t.Fatal("the condemnation did not survive a live success")
	}
}

// TestProbeNowForgivesTheNodesCondemnation is the other half: the ONE way back. The node fires this
// itself once it has walked the whole pool and the tunnel is still dead — which is it saying the
// problem was never these IPs — and the panel offers the same control.
func TestProbeNowForgivesTheNodesCondemnation(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	nodeBurn(p)
	p.probeAllNow()
	due := p.dueRetests()
	if len(due) != 1 || due[0] != "a" {
		t.Fatalf("after probe now the endpoint must be probeable again, got %v", due)
	}
	if !p.retestResult("a", true) {
		t.Fatal("an answered probe must now re-admit it")
	}
	// An operator pin says the same thing about one endpoint.
	nodeBurn(p)
	p.selectEntry("a")
	p.mu.Lock()
	burned := p.health["a"] != nil
	p.mu.Unlock()
	if burned {
		t.Fatal("a pin must clear the burn and the condemnation with it")
	}
}

// TestSourceHealAndDialBurnStillHeal guards what the rule must NOT break. A SOURCE burn is cleared by a
// returning frame — that is the only question a source burn asks, and nothing else can probe a source —
// and so is a burn nothing marked, which is how a tcp carrier's dial failure is answered by a
// connection that later came up on the same endpoint.
func TestSourceHealAndDialBurnStillHeal(t *testing.T) {
	for _, name := range []string{"source pool", "unmarked carrier burn"} {
		t.Run(name, func(t *testing.T) {
			p := NewPeerPool([]string{"a", "b"}, true, 0, "")
			p.fail() // burn "a", NOT marked as the node's
			p.mu.Lock()
			p.cur, p.chosen = 0, ""
			p.mu.Unlock()
			if healed := p.succeeded(); healed != "a" {
				t.Fatalf("an unmarked burn must still heal on a live success, got %q", healed)
			}
		})
	}
}

// TestHealEventsLeavesACondemnedDestinationBurned drives the exact path every datagram carrier's
// clientLoop takes when its endpoint answers — healEvents -> rotationController.success. The source
// heals and emits its event; the condemned destination does neither.
func TestHealEventsLeavesACondemnedDestinationBurned(t *testing.T) {
	dir := t.TempDir()
	st := newCoreStatus(filepath.Join(dir, "core.json"), "udp · test", roleOf(true))
	dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, true, 0, "")
	src := NewPeerPool([]string{"192.0.2.1", "192.0.2.2"}, true, 0, "")
	nodeBurn(dst)
	src.fail()
	for _, p := range []*PeerPool{dst, src} { // both cursors back on the burned entry, and it is answering
		p.mu.Lock()
		p.cur, p.chosen = 0, ""
		p.mu.Unlock()
	}
	healEvents(st, newRotationController(dst, src))
	dst.mu.Lock()
	stillBurned := dst.health["10.0.0.1"] != nil
	dst.mu.Unlock()
	if !stillBurned {
		t.Fatal("a returning frame re-admitted a condemned destination")
	}
	src.mu.Lock()
	srcHealed := src.health["192.0.2.1"] == nil
	src.mu.Unlock()
	if !srcHealed {
		t.Fatal("the source pool has no prober, so a returning frame is still its heal")
	}
	st.mu.Lock()
	evs := append([]coreEvent(nil), st.events...)
	st.mu.Unlock()
	if len(evs) != 1 || evs[0].Code != "src-retest" {
		t.Fatalf("want exactly one src-retest event, got %+v", evs)
	}
}

// TestTCPFailCommandCondemnsItsDestination drives the node's command through the real cmd-file path a
// direct-tcp client polls, and then the real post-serve heal, to prove the mark survives both. tcp's
// heal is NOT on connect — succeedBoth runs when a carrier that lived a healthy life goes away — so
// the test brings the tunnel up on an all-burned pool and takes it down the way the pin poller does.
func TestTCPFailCommandCondemnsItsDestination(t *testing.T) {
	const psk = "tcp-condemn-pre-shared-key-1234567890"
	srvDev, srvCtrl := tunPair(t, "tcsrv")
	cliDev, cliCtrl := tunPair(t, "tccli")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
	srv, err := ListenTCP([]string{a1, a2}, srvDev, time.Second, false, true, psk, "aes-256-gcm", false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	cli, err := DialTCP(a1, cliDev, time.Second, false, true, psk, "aes-256-gcm", false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	dir := t.TempDir()
	cli.SetStatusPath(filepath.Join(dir, "core.json"))
	p := NewPeerPool([]string{a1, a2}, true, 0, filepath.Join(dir, "pool.json"))
	cli.SetPeerPool(p)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	pkt := bytes.Repeat([]byte{0xA9}, 160)
	deadline := time.Now().Add(15 * time.Second)
	for cli.cur.Load() == nil {
		if _, werr := cliCtrl.Write(pkt); werr != nil {
			t.Fatalf("inject: %v", werr)
		}
		if time.Now().After(deadline) {
			t.Fatal("the pooled tcp client never connected")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The node's ask, through the file the core really polls. It burns the active endpoint, marks it,
	// and drops the carrier; the client re-dials on the other one.
	gone := p.current()
	writeFileAtomic(p.cmdPath(), []byte(`{"cmd":"fail"}`), 0o644)
	deadline = time.Now().Add(15 * time.Second)
	for {
		p.mu.Lock()
		r := p.health[gone]
		marked := r != nil && r.nodeBurn
		p.mu.Unlock()
		if marked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fail command never condemned %s", gone)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Now take the carrier down the deliberate way, which is the branch that reaches succeedBoth.
	old := cli.cur.Load()
	cli.manualSwitch.Store(true)
	if c := cli.curConn.Load(); c != nil {
		(*c).Close()
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		if cur := cli.cur.Load(); cur != nil && cur != old {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came back after the deliberate drop")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for {
		if _, werr := cliCtrl.Write(pkt); werr != nil {
			t.Fatalf("inject after the drop: %v", werr)
		}
		if got := readWithTimeout(t, srvCtrl, "client->server after the drop"); len(got) > 0 {
			break
		}
	}
	p.mu.Lock()
	r := p.health[gone]
	p.mu.Unlock()
	if r == nil {
		t.Fatalf("a healthy carrier cleared the condemnation on %s — only the tun probe may take that back", gone)
	}
}
