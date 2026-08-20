package packet

import (
	"bytes"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func newSoakClient(t *testing.T, rotate time.Duration) (*TCP, *wsPool, *os.File, *os.File) {
	t.Helper()
	const psk = "rotation-soak-psk-abcdefghijklmnop"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "soaksrv")
	cliDev, cliCtrl := tunPair(t, "soakcli")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, false, true, psk, cipher, "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	pool := newWSPool([]string{addr}, snis("front-a", "front-b"))
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, psk: psk,
		ws: true, wsTLS: false, pool: pool, rotate: rotate,
		idle: connIdle, ping: pingEvery, isClient: true, addr: "pool", closeCh: make(chan struct{})}
	cli.SetStatusPath(runningStatusPath(t, cli))
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	waitFor(t, 5*time.Second, "active up", func() bool { return cli.cur.Load() != nil })
	return cli, pool, cliCtrl, srvCtrl
}

func drainCounter(ctrl *os.File, n *int64) {
	go func() {
		buf := make([]byte, 2048)
		for {
			m, err := ctrl.Read(buf)
			if m > 0 {
				atomic.AddInt64(n, 1)
			}
			if err != nil {
				return
			}
		}
	}()
}

func TestRotationSoakRapidRotate(t *testing.T) {
	cli, _, cliCtrl, srvCtrl := newSoakClient(t, 150*time.Millisecond)

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	seen := map[string]int{}
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		tk := time.NewTicker(25 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				if a := poolActive(cli); a != "" {
					seen[a]++
				}
			}
		}
	}()

	pkt := bytes.Repeat([]byte{0x7E}, 160)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("client write: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)

	<-sampled

	distinct := len(seen)
	if distinct < 2 {
		t.Fatalf("rotation appears frozen: saw only %d distinct active edge(s) across 3s of 150ms rotation (want >= 2): %v", distinct, seen)
	}
	if cli.cur.Load() == nil {
		t.Fatal("tunnel has no active carrier after the rapid-rotate soak")
	}
	if got := atomic.LoadInt64(&delivered); got == 0 {
		t.Fatal("no data traversed the tunnel during rapid rotation — the tunnel was dead throughout")
	}
	t.Logf("rapid-rotate soak: %d distinct active edges, %d packets delivered through the churn: %v",
		distinct, atomic.LoadInt64(&delivered), seen)
}

func TestRotationSoakPinStorm(t *testing.T) {
	cli, _, cliCtrl, srvCtrl := newSoakClient(t, 0)

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	stop := make(chan struct{})
	go func() {
		targets := []string{"front-a", "front-b"}
		i := 0
		tk := time.NewTicker(60 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				writeFileAtomic(cli.st.pinPath(),
					[]byte(`{"kind":"sni","key":"`+targets[i%2]+`"}`), 0o644)
				i++
			}
		}
	}()

	pkt := bytes.Repeat([]byte{0x5C}, 140)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("client write during pin storm: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}
	close(stop)

	waitFor(t, 5*time.Second, "active still up after pin storm", func() bool { return cli.cur.Load() != nil })
	if got := atomic.LoadInt64(&delivered); got == 0 {
		t.Fatal("no data traversed the tunnel during the pin storm")
	}
	t.Logf("pin-storm soak: survived, %d packets delivered through the storm", atomic.LoadInt64(&delivered))
}

func TestRotationSoakFailoverStorm(t *testing.T) {
	cli, _, cliCtrl, srvCtrl := newSoakClient(t, 0)

	var delivered int64
	drainCounter(srvCtrl, &delivered)

	pkt := bytes.Repeat([]byte{0x93}, 150)
	for cycle := 0; cycle < 15; cycle++ {
		if a := cli.cur.Load(); a != nil {
			a.conn.Close()
		}

		waitFor(t, 6*time.Second, "carrier recovered after kill", func() bool { return cli.cur.Load() != nil })

		before := atomic.LoadInt64(&delivered)
		resumed := false
		for try := 0; try < 60 && !resumed; try++ {
			if _, err := cliCtrl.Write(pkt); err != nil {
				t.Fatalf("cycle %d: client write: %v", cycle, err)
			}
			if atomic.LoadInt64(&delivered) > before {
				resumed = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !resumed {
			t.Fatalf("cycle %d: tunnel did not resume data flow within 3s after failover", cycle)
		}
	}
	t.Logf("failover-storm soak: survived 15 active-carrier kills with data recovery each time (%d pkts)",
		atomic.LoadInt64(&delivered))
}
