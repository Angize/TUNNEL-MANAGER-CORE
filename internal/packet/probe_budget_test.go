package packet

import (
	"net"
	"testing"
	"time"
)

// silentTLSEdge accepts TCP and then says nothing at all — the shape of a blocked or tarpitting CDN
// edge, and the one that makes a TLS handshake hang rather than fail.
func silentTLSEdge(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	held := make(chan net.Conn, 16)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			select {
			case held <- c: // hold it open, never read, never write
			default:
				c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		close(held)
		for c := range held {
			c.Close()
		}
	})
	return ln.Addr().String()
}

// probe_timeout_secs must bound the TLS leg of an edge probe, not just the dial and the header wait.
// uEdgeHandshake arms the socket deadline itself, so a deadline armed just before calling it is
// overwritten by its own fixed one. Both carriers are asserted: on ws nothing else bounds the handshake,
// so a silent edge costs a flat 10s per probe; on http/grpc the header timeout caps it at 3× the budget.
func TestProbeTimeoutBoundsTheTLSHandshake(t *testing.T) {
	const budget = 2 * time.Second
	p0 := probeTimeout
	probeTimeout = budget
	t.Cleanup(func() { probeTimeout = p0 })

	for _, tc := range []struct {
		name  string
		build func(addr string) *TCP
	}{
		{"ws", func(addr string) *TCP {
			return &TCP{addr: addr, ws: true, wsPath: "/", wsTLS: true, wsHost: "cdn.example.com"}
		}},
		{"httpc-post", func(addr string) *TCP {
			return &TCP{addr: addr, ws: true, httpc: true, httpcMode: "post", wsPath: "/", wsTLS: true, wsHost: "cdn.example.com"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := silentTLSEdge(t)
			b := tc.build(addr)
			t0 := time.Now()
			healthy := b.probeEdgeFull(addr, wsSNIEntry{host: "cdn.example.com", path: "/"})
			elapsed := time.Since(t0)
			if healthy {
				t.Fatal("an edge that never answers the ClientHello probed HEALTHY")
			}
			// Generous: the dial is instant on loopback, so with the budget honoured this is one
			// budget plus scheduling. The failing case is 10s (ws) or 3xbudget (httpc).
			if limit := 2 * budget; elapsed > limit {
				t.Errorf("the probe took %v against a probe_timeout_secs of %v: the TLS leg is bounded by uEdgeHandshake's fixed handshakeTimeout, not by the operator's budget",
					elapsed.Round(10*time.Millisecond), budget)
			}
			t.Logf("probe returned in %v on a %v budget", elapsed.Round(10*time.Millisecond), budget)
		})
	}
}
