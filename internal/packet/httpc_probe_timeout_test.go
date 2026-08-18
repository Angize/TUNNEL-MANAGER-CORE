package packet

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestHTTPCProbeHonoursProbeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})

	old := probeTimeout
	probeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })

	b := &TCP{httpc: true, httpcMode: "post"}
	start := time.Now()
	reachable := b.probeEdgeFull(ln.Addr().String(), wsSNIEntry{host: "front.example"})
	el := time.Since(start)

	if reachable {
		t.Fatal("an edge that never answers was reported reachable — a dead http edge would heal on retest")
	}

	if lim := 6 * probeTimeout; el > lim {
		t.Fatalf("the probe took %v on a %v budget (limit %v) — probe_timeout_secs does not reach the http/grpc path", el, probeTimeout, lim)
	}
}

func TestHTTPCLiveEstablishKeepsItsTimings(t *testing.T) {
	if handshakeTimeout != 10*time.Second {
		t.Fatalf("the live connect budget is %v; this test's expectations were written for 10s", handshakeTimeout)
	}
	if got := httpcHeaderWait(handshakeTimeout); got != 30*time.Second {
		t.Fatalf("the live header wait is %v, want the previous fixed 30s", got)
	}
	if got := httpcHeaderWait(probeTimeout); got >= httpcHeaderWait(handshakeTimeout) {
		t.Fatalf("a probe's header wait (%v) is not shorter than the live one (%v) — the probe budget is not actually reaching it", got, httpcHeaderWait(handshakeTimeout))
	}
}
