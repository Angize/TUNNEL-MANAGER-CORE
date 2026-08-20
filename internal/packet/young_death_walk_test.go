package packet

import (
	"testing"
	"time"
)

func wsPoolClient(t *testing.T, tag string, hosts []string, addrs ...string) (*TCP, *wsPool) {
	t.Helper()
	const psk = "ws-young-death-psk-abcdefghijkl"
	const cipher = "aes-256-gcm"
	for i, a := range addrs {
		dev, _ := tunPair(t, tag+"s"+string(rune('0'+i)))
		srv, err := ListenWS(a, dev, false, true, psk, cipher, "")
		if err != nil {
			t.Fatalf("ListenWS %s: %v", a, err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })
	}
	cliDev, _ := tunPair(t, tag+"c")
	pool := newWSPool(addrs, snis(hosts...))
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, psk: psk,
		ws: true, wsTLS: false, pool: pool,
		idle: connIdle, ping: pingEvery, isClient: true, addr: "pool", closeCh: make(chan struct{})}
	cli.SetStatusPath(runningStatusPath(t, cli))
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	return cli, pool
}

func liveEdge(cli *TCP) string {
	if c := cli.curConn.Load(); c != nil {
		return (*c).RemoteAddr().String()
	}
	return ""
}

func poolEvents(b *TCP, code string) int {
	b.st.mu.Lock()
	defer b.st.mu.Unlock()
	n := 0
	for _, e := range b.st.events {
		if e.Code == code {
			n++
		}
	}
	return n
}

func TestAYoungDeathWalksOneLapAndStops(t *testing.T) {
	cli, pool := wsPoolClient(t, "ywlk", []string{"h1", "h2", "h3"}, freeTCPPort(t))
	lap := pool.comboCount()
	if lap != 3 {
		t.Fatalf("one lap of this pool is %d combinations, want 3 — the budget under test is mis-sized", lap)
	}

	deaths, changes, last := 0, 0, ""
	tail := 0
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

	if n := poolEvents(cli, "edge-walk"); n != 1 {
		t.Errorf("the walk wrote %d edge-walk events for one outage (%d steps), want exactly 1", n, changes)
	}
}

func TestAYoungDeathLeavesADeadEdge(t *testing.T) {
	bad, good := freeTCPPort(t), freeTCPPort(t)
	cli, _ := wsPoolClient(t, "ylve", []string{"h1"}, bad, good)

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		cc := cli.curConn.Load()
		if cc == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if liveEdge(cli) == good {

			time.Sleep(2 * time.Second)
			if at := liveEdge(cli); at != good {
				t.Fatalf("it reached the good edge and left again, now on %q", at)
			}
			return
		}
		(*cc).Close()
		for cli.curConn.Load() == cc && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatalf("stranded on the dead edge %s for the whole run — nothing moved the tunnel off a combination "+
		"that dies too young for the probe to condemn", bad)
}
