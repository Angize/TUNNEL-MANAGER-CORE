package packet

import (
	"net"
	"path/filepath"
	"testing"
)

// A dial that never came up is the one fact about an edge that cannot be faked. A filtered edge passes
// a probe and swallows the payload; it cannot answer a handshake it dropped. So the dial itself is
// evidence, and it is the only evidence the core produces without the node.
func TestAnEdgeThatWillNotDialIsBurned(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close() // nothing listens there any more: connect refused

	p := newWSPool([]string{dead, "127.0.0.2:1"}, snis("x"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))

	ip, _, _ := p.current()
	if ip != dead {
		t.Fatalf("setup: the pool starts on %q, want %q", ip, dead)
	}
	if _, _, _, err := b.dialCarrier(); err == nil {
		t.Fatal("setup: the dial to a closed port succeeded")
	}

	p.mu.Lock()
	burned := !p.ipHealth.healthy(dead)
	p.mu.Unlock()
	if !burned {
		t.Fatalf("%s refused the connection and stayed healthy. Nothing else in the core will ever say "+
			"so: the node's probe only judges the tunnel it is carried on, and this one never came up", dead)
	}
}

// The SNI is not what a refused connection proves anything about — the bytes never got far enough to
// carry one. A one-SNI pool would otherwise condemn the only domain it has.
func TestADialFailureBlamesTheEdgeNotTheDomain(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()

	p := newWSPool([]string{dead, "127.0.0.2:1"}, snis("only.example"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	b.dialCarrier()

	p.mu.Lock()
	sniBurned := !p.sniHealth.healthy("only.example")
	p.mu.Unlock()
	if sniBurned {
		t.Fatal("a refused TCP connection condemned the domain — the handshake that carries an SNI never " +
			"happened, and this pool has no second domain to fall back to")
	}
}

// A verdict about a combination the pool has left still names a real failure, so it must still burn --
// but on the axis the walk would have varied. With one edge there is nothing to vary under the domain,
// and the domain is what a failure condemns instead.
func TestAStaleComboVerdictBurnsTheAxisTheWalkVaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ips   []string
		burnt string // "sni" or "ip"
	}{
		{"two edges: the low digit takes it", []string{"e1", "e2"}, "ip"},
		{"one edge: nothing varies under the domain, so the domain takes it", []string{"only"}, "sni"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, p := edgeCarrier(t, tc.ips, snis("s1", "s2"))

			measIP, measSNI, _ := p.current()
			b.pretendConnected(measIP, measSNI.host)
			if !p.advance() {
				t.Fatal("setup: the pool would not move")
			}

			// The carrier is DOWN, so the published pair follows the cursor -- which is exactly the
			// window this arm exists for: the probe measured the pair we have just left.
			b.pretendDown()
			b.tunFail(t, measIP, measSNI.host)

			p.mu.Lock()
			sniBurned := !p.sniHealth.healthy(measSNI.host)
			ipBurned := !p.ipHealth.healthy(measIP)
			p.mu.Unlock()

			if tc.burnt == "ip" && (!ipBurned || sniBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with a second edge the low digit is what a failed "+
					"combination condemns; convicting the domain here loses it on every edge at once",
					sniBurned, ipBurned)
			}
			if tc.burnt == "sni" && (!sniBurned || ipBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with one edge there is no low digit, and burning it "+
					"takes the only edge the tunnel has", sniBurned, ipBurned)
			}
		})
	}
}

func TestABurnNeverLandsOnThePinnedEntry(t *testing.T) {
	for _, tc := range []struct{ kind, key string }{{"ip", "e1"}, {"sni", "s1"}} {
		p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"))
		if !p.selectEntry(tc.kind, tc.key) {
			t.Fatalf("%s: selectEntry(%s) did not find it", tc.kind, tc.key)
		}
		p.markSuspect(tc.kind, tc.key, "dial")
		if !p.healthMap(tc.kind).healthy(tc.key) {
			t.Fatalf("%s: a dial failure burned the PINNED %s. selectEntry stashed its record in "+
				"pinTook, so releasing the pin would restore the old record and erase this burn -- and "+
				"meanwhile the operator's own choice reads as burned on the panel", tc.kind, tc.key)
		}

		p.releasePin()
		p.markSuspect(tc.kind, tc.key, "dial")
		if p.healthMap(tc.kind).healthy(tc.key) {
			t.Fatalf("%s: once the pin is gone the very next dial failure must burn %s -- the pin defers "+
				"the evidence, it does not throw it away", tc.kind, tc.key)
		}
	}
}
