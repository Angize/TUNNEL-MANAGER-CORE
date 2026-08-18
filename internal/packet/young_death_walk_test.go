package packet

import (
	"testing"
	"time"
)

// wsPoolClient stands up a real ws server per address and a pooled client on Run(), so these tests
// exercise dialLoop's own death path rather than any helper it happens to call.
func wsPoolClient(t *testing.T, tag string, hosts []string, addrs ...string) (*TCP, *wsPool) {
	t.Helper()
	const psk = "ws-young-death-psk-abcdefghijkl"
	const cipher = "aes-256-gcm"
	for i, a := range addrs {
		dev, _ := tunPair(t, tag+"s"+string(rune('0'+i)))
		srv, err := ListenWS(a, dev, time.Second, false, true, psk, cipher, "")
		if err != nil {
			t.Fatalf("ListenWS %s: %v", a, err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })
	}
	cliDev, _ := tunPair(t, tag+"c")
	pool := newWSPool(addrs, snis(hosts...), "")
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, keepalive: time.Second, psk: psk,
		ws: true, wsTLS: false, pool: pool,
		idle: deadWindow(time.Second), isClient: true, addr: "pool", closeCh: make(chan struct{})}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	return cli, pool
}

// liveEdge returns the address the client's connection is REALLY on, "" while it is between dials. The
// pool's cursor is not the same thing — a walk moves it before the next dial — and every claim here is
// about where the tunnel actually is.
func liveEdge(cli *TCP) string {
	if c := cli.curConn.Load(); c != nil {
		return (*c).RemoteAddr().String()
	}
	return ""
}

// TestAYoungDeathWalksOneLapAndStops bounds the free walk.
//
// A carrier that comes up and dies too fast for the node's probe to have judged it may step the cursor
// — otherwise a combination that never holds still long enough to be condemned strands the tunnel
// forever. But it may do so for ONE lap only. Past that every combination has been tried and none of
// them held, so the fault is in none of them, and walking on only denies the probe a path that stays
// put long enough to measure. Before this bound existed the walk ran at roughly 1 Hz for as long as the
// outage lasted.
func TestAYoungDeathWalksOneLapAndStops(t *testing.T) {
	cli, pool := wsPoolClient(t, "ywlk", []string{"h1", "h2", "h3"}, freeTCPPort(t))
	lap := pool.comboCount()
	if lap != 3 {
		t.Fatalf("one lap of this pool is %d combinations, want 3 — the budget under test is mis-sized", lap)
	}

	// Kill every carrier the instant it appears: every death is far inside minLiveness.
	deaths, changes, last := 0, 0, ""
	tail := 0 // consecutive deaths at the end that moved nothing
	deadline := time.Now().Add(30 * time.Second)
	for deaths < 4*lap && time.Now().Before(deadline) {
		cc := cli.curConn.Load()
		if cc == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if at := liveEdge(cli); at != "" {
			_, sni, _ := pool.current()
			if cur := at + " · " + sni.host; cur != last {
				if last != "" {
					changes++
					tail = 0
				}
				last = cur
			} else {
				tail++
			}
		}
		deaths++
		(*cc).Close()
		for cli.curConn.Load() == cc && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if deaths < 4*lap {
		t.Fatalf("only %d deaths in the budget window; the client stopped re-dialing", deaths)
	}
	if changes == 0 {
		t.Fatal("the walk never moved: a combination that dies too young to be judged strands the tunnel")
	}
	if changes > lap {
		t.Fatalf("the walk stepped %d times over %d deaths — one lap is %d; it is unbounded", changes, deaths, lap)
	}
	if tail == 0 {
		t.Fatal("the walk was still moving on the last death — it never settled for the probe to measure")
	}
}

// TestAYoungDeathLeavesADeadEdge is the other half, and the one that makes deleting the walk outright
// impossible.
//
// One edge accepts a connection and loses it at once; the other works. The probe cannot break the tie —
// a measurement takes most of a second and this carrier never survives that long — so if the carrier
// holds still waiting for a verdict, it waits on the dead edge for good. Measured before this test
// existed: with the walk removed the client sat on the bad edge for the entire run.
func TestAYoungDeathLeavesADeadEdge(t *testing.T) {
	bad, good := freeTCPPort(t), freeTCPPort(t)
	cli, _ := wsPoolClient(t, "ylve", []string{"h1"}, bad, good) // bad first: the client starts on it

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		cc := cli.curConn.Load()
		if cc == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if liveEdge(cli) == good {
			// It left the dead edge. Hold it here long enough to outlast minLiveness-driven churn.
			time.Sleep(2 * time.Second)
			if at := liveEdge(cli); at != good {
				t.Fatalf("it reached the good edge and left again, now on %q", at)
			}
			return
		}
		(*cc).Close() // only the bad edge's carriers are killed
		for cli.curConn.Load() == cc && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatalf("stranded on the dead edge %s for the whole run — nothing moved the tunnel off a combination "+
		"that dies too young for the probe to condemn", bad)
}
