package packet

import (
	"net"
	"sync"
	"testing"
	"time"
)

type writeRecorder struct {
	net.Conn
	mu    sync.Mutex
	sizes []int
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.sizes = append(w.sizes, len(p))
	w.mu.Unlock()
	return w.Conn.Write(p)
}

func (w *writeRecorder) snapshot() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]int(nil), w.sizes...)
}

func TestObfsSaltNeverGetsAWriteOfItsOwn(t *testing.T) {
	const psk = "obfs-salt-ride-pre-shared-key-123"
	const cipher = "aes-256-gcm"
	const ka = time.Second
	const rounds = 8

	srvDev, _ := tunPair(t, "saltsrv")
	addr := freeTCPPort(t)
	srv, err := ListenTCP([]string{addr}, srvDev, true, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	srvRecs := make(chan *writeRecorder, rounds)
	go func() {
		for {
			c, aerr := srv.ln.Accept()
			if aerr != nil {
				return
			}
			rec := &writeRecorder{Conn: c}
			srvRecs <- rec
			go srv.handleServerConn(rec)
		}
	}()

	cliDev, _ := tunPair(t, "saltcli")
	var cliLast, srvLast []int
	for i := 0; i < rounds; i++ {
		raw, derr := net.Dial("tcp", addr)
		if derr != nil {
			t.Fatalf("round %d: dial: %v", i, derr)
		}
		cliRec := &writeRecorder{Conn: raw}
		cli, cerr := DialTCP(addr, cliDev, true, true, psk, cipher, false, "")
		if cerr != nil {
			t.Fatalf("round %d: DialTCP: %v", i, cerr)
		}
		cf, herr := cli.handshakeAndPrime(cliRec)
		if herr != nil {
			t.Fatalf("round %d: handshakeAndPrime: %v", i, herr)
		}

		_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, _, _, rerr := cf.readFrame(); rerr != nil {
			t.Fatalf("round %d: reading the server's answer: %v", i, rerr)
		}

		var srvRec *writeRecorder
		select {
		case srvRec = <-srvRecs:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: the server never accepted", i)
		}

		for _, side := range []struct {
			name  string
			sizes []int
		}{{"client", cliRec.snapshot()}, {"server", srvRec.snapshot()}} {
			if len(side.sizes) < 2 {
				t.Fatalf("round %d %s: only %d writes (%v) — the exchange did not happen",
					i, side.name, len(side.sizes), side.sizes)
			}
			for _, n := range side.sizes {
				if n == obfsSaltLen {
					t.Fatalf("round %d %s: a write of exactly %d bytes (all writes: %v) — that is the "+
						"bare salt getting its own record, the same size on every connection in both "+
						"directions, which is exactly the fingerprint obfs padding exists to remove",
						i, side.name, obfsSaltLen, side.sizes)
				}
			}
			last := side.sizes[len(side.sizes)-1]
			if last <= obfsSaltLen {
				t.Fatalf("round %d %s: the salt-carrying write is %d bytes, want more than the %d-byte "+
					"salt — it must carry a padded frame with it", i, side.name, last, obfsSaltLen)
			}
			if side.name == "client" {
				cliLast = append(cliLast, last)
			} else {
				srvLast = append(srvLast, last)
			}
		}
		raw.Close()
	}

	for _, side := range []struct {
		name string
		vals []int
	}{{"client", cliLast}, {"server", srvLast}} {
		distinct := map[int]bool{}
		for _, v := range side.vals {
			distinct[v] = true
		}
		if len(distinct) < 2 {
			t.Fatalf("%s: the first-frame write was %v across %d connections — one constant size is "+
				"still a fingerprint, just a longer one", side.name, side.vals, rounds)
		}
	}
}
