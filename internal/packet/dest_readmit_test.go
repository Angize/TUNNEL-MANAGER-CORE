package packet

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestBurnLadderClimbsAcrossHeals is the arithmetic behind the whole change. A destination that is
// burned, re-admitted and burned again used to re-enter suspect at the FIRST backoff step every single
// time, so the 30/60/120/… ladder never climbed and the same endpoint could be picked up and dropped on
// every rotation forever. Each episode must now start one step further down.
func TestBurnLadderClimbsAcrossHeals(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	for i, want := range suspectBackoff {
		p.mu.Lock()
		p.cur, p.chosen = 0, ""
		p.mu.Unlock()
		p.fail() // burn a
		p.mu.Lock()
		r := p.health["a"]
		fails, next := r.fails, r.nextRetest
		p.mu.Unlock()
		if fails != i || next != clk+want {
			t.Fatalf("burn #%d should enter suspect at step %d (+%ds), got fails=%d next=+%d", i+1, i, want, fails, next-clk)
		}
		p.retestResult("a", true) // the prober re-admits it; the HISTORY must survive
		p.mu.Lock()
		healed := p.health["a"] == nil
		p.mu.Unlock()
		if !healed {
			t.Fatal("an answered probe must re-admit the endpoint")
		}
	}
	// The ladder is spent: the next burn goes straight back to dead on the slow retest.
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.fail()
	p.mu.Lock()
	r := p.health["a"]
	state, next := r.state, r.nextRetest
	p.mu.Unlock()
	if state != stateDead || next != clk+deadRetest {
		t.Fatalf("with the ladder spent the next burn should be dead at +%ds, got %s at +%d", deadRetest, state, next-clk)
	}
}

// TestProbeAllNowForgetsTheLadder is the escape hatch that keeps a wrong burn from being permanent. The
// panel's "probe now" — which the node also reaches for once it has walked the whole pool and is STILL
// red — says the problem was never these IPs, so the history goes with the burns.
func TestProbeAllNowForgetsTheLadder(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	for i := 0; i < 3; i++ {
		p.mu.Lock()
		p.cur, p.chosen = 0, ""
		p.mu.Unlock()
		p.fail()
		p.retestResult("a", true)
	}
	p.probeAllNow()
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.fail()
	p.mu.Lock()
	r := p.health["a"]
	fails, next := r.fails, r.nextRetest
	p.mu.Unlock()
	if fails != 0 || next != clk+suspectBackoff[0] {
		t.Fatalf("after probe now the ladder should start over at +%ds, got fails=%d next=+%d", suspectBackoff[0], fails, next-clk)
	}
	// A deliberate operator pin says the same thing about ONE endpoint.
	p.retestResult("a", true)
	p.selectEntry("a")
	p.mu.Lock()
	p.pinKey, p.pinUntil = "", 0 // release the pin so fail() may burn again
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.fail()
	p.mu.Lock()
	fails = p.health["a"].fails
	p.mu.Unlock()
	if fails != 0 {
		t.Fatalf("a pin should start the pinned endpoint over, got fails=%d", fails)
	}
}

// TestHealEventsLeavesTheDestinationBurned drives the exact path every datagram carrier's clientLoop
// takes when its endpoint answers — healEvents -> rotationController.success. A returning frame heals
// the SOURCE (that is the only question a source burn asks) and must NOT touch a destination the prober
// owns: it says an endpoint answered us, never that the tunnel carries, and the node's tun probe is what
// judges that. One reply one second after a rotation used to wipe a burn the node had just measured.
// The crypto-off case is the control: with no prober to own it, the old rule is all there is.
func TestHealEventsLeavesTheDestinationBurned(t *testing.T) {
	for _, probed := range []bool{true, false} {
		name := "with a prober"
		if !probed {
			name = "without one (crypto-off udp)"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			st := newCoreStatus(filepath.Join(dir, "core.json"), "udp · test", roleOf(true))
			dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, true, 0, "")
			src := NewPeerPool([]string{"192.0.2.1", "192.0.2.2"}, true, 0, "")
			if probed {
				dst.proberOwned()
			}
			dst.fail() // burn 10.0.0.1, cursor moves to .2
			src.fail() // burn 192.0.2.1, cursor moves to .2
			// Put both cursors back on the burned entry: the carrier is on it and it is answering.
			for _, p := range []*PeerPool{dst, src} {
				p.mu.Lock()
				p.cur, p.chosen = 0, ""
				p.mu.Unlock()
			}
			healEvents(st, newRotationController(dst, src))
			dst.mu.Lock()
			stillBurned := dst.health["10.0.0.1"] != nil
			dst.mu.Unlock()
			if stillBurned != probed {
				t.Fatalf("destination still burned = %v, want %v", stillBurned, probed)
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
			want := []string{"src-retest"}
			if !probed {
				want = []string{"peer-retest", "src-retest"}
			}
			if len(evs) != len(want) {
				t.Fatalf("want %v, got %+v", want, evs)
			}
			for i, code := range want {
				if evs[i].Code != code {
					t.Fatalf("event %d = %q, want %q", i, evs[i].Code, code)
				}
			}
		})
	}
}

// TestTCPHealthyCarrierDoesNotReadmitItsDestination is the same rule on the carrier that had its own
// copy of it. tcp's heal is NOT on connect — succeedBoth runs on the post-serve path, when a carrier
// that lived a healthy life goes away or an operator switch takes it down — so the test drives exactly
// that: bring a pooled client up on an all-burned pool, then take the carrier down the way the pin
// poller does. The burn on the endpoint it was using must survive. The prober cannot interfere: it
// skips the ACTIVE endpoint, and the other one's retest is an hour out.
func TestTCPHealthyCarrierDoesNotReadmitItsDestination(t *testing.T) {
	const psk = "tcp-readmit-pre-shared-key-1234567890"
	srvDev, srvCtrl := tunPair(t, "trsrv")
	cliDev, cliCtrl := tunPair(t, "trcli")
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
	p := NewPeerPool([]string{a1, a2}, true, 0, "")
	// Both endpoints burned and NOT yet due: the client must still come up (current() never dead-ends)
	// on the least-bad one, and no probe is due for either.
	p.mu.Lock()
	far := p.now() + 3600
	p.health[a1] = &healthRec{state: stateSuspect, nextRetest: far}
	p.health[a2] = &healthRec{state: stateSuspect, nextRetest: far}
	p.mu.Unlock()
	cli.SetPeerPool(p)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	pkt := bytes.Repeat([]byte{0xA9}, 160)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, werr := cliCtrl.Write(pkt); werr != nil {
			t.Fatalf("inject: %v", werr)
		}
		if cli.cur.Load() != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pooled tcp client never connected")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); len(got) == 0 {
		t.Fatal("the tunnel never carried")
	}
	active := p.current()

	// Take the carrier down exactly as the pin poller's drop() does — a deliberate switch, which is the
	// branch that reaches succeedBoth without waiting out minLiveness.
	old := cli.cur.Load()
	cli.manualSwitch.Store(true)
	if c := cli.curConn.Load(); c != nil {
		(*c).Close()
	}
	// A DIFFERENT framer means the dial loop went all the way round, and succeedBoth sits on that path
	// before the re-dial — so by here it has certainly run.
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
	r := p.health[active]
	p.mu.Unlock()
	if r == nil {
		t.Fatalf("a healthy carrier on %s cleared its burn — a connection that lived says the endpoint "+
			"accepted us, not that the tunnel carries", active)
	}
}
