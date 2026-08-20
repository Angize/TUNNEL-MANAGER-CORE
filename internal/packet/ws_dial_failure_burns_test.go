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

	p := newWSPool([]string{dead, "127.0.0.2:1"}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.armEdgeWalk()

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

	p := newWSPool([]string{dead, "127.0.0.2:1"}, snis("only.example"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.armEdgeWalk()
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
// but on the axis the walk would have varied. With one SNI there is nothing to vary, and blaming it
// would condemn the only domain the tunnel has.
func TestAStaleComboVerdictBurnsTheAxisTheWalkVaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		snis  []string
		burnt string // "sni" or "ip"
	}{
		{"two SNIs: the low digit takes it", []string{"s1", "s2"}, "sni"},
		{"one SNI: nothing varies under the edge, so the edge takes it", []string{"only"}, "ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := newWSPool([]string{"e1", "e2"}, snis(tc.snis...), filepath.Join(dir, "st.json"))
			b := &TCP{isClient: true, ws: true, pool: p}
			b.st = newCoreStatus(filepath.Join(dir, "core.status"), "ws · pool")
			b.armEdgeWalk()

			measIP, measSNI, _ := p.current()
			p.setActive(activeLabel(measIP, measSNI.host))
			if !p.advance() {
				t.Fatal("setup: the pool would not move")
			}
			p.tracker.observe(pathKey{Dst: measIP, Dport: 443, Sport: 1, SNI: measSNI.host}, true)
			liveVerdict(t, p.cmdPath(), p.pathEpoch(),
				poolCmd{Cmd: cmdFail, IP: measIP, SNI: measSNI.host})
			b.pollWsCmd()

			p.mu.Lock()
			sniBurned := !p.sniHealth.healthy(measSNI.host)
			ipBurned := !p.ipHealth.healthy(measIP)
			p.mu.Unlock()

			if tc.burnt == "sni" && (!sniBurned || ipBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with a second SNI the low digit is what a failed "+
					"combination condemns; convicting the edge here skips a whole row", sniBurned, ipBurned)
			}
			if tc.burnt == "ip" && (!ipBurned || sniBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with one SNI there is no low digit, and burning it "+
					"takes the only domain the tunnel has", sniBurned, ipBurned)
			}
		})
	}
}

// The rotation's own sequence: look at where we are, step, try to build a carrier there, and on failure
// put the cursor back. The live carrier is never let go -- and the edge that would not answer is burned
// on the way, by the dial itself, so the next rotation has nothing eligible to walk onto and stops
// hammering it until its backoff elapses.
func TestARotationOntoADeadEdgeKeepsTheCarrierAndBurnsIt(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	const live = "127.0.0.9:443"

	p := newWSPool([]string{live, dead}, snis("x"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.armEdgeWalk()
	b.warmNext = make(chan *warmDial, 1)

	prevIP, prevSNI, ok := p.current()
	if !ok || prevIP != live {
		t.Fatalf("setup: the pool starts on %q, want %q", prevIP, live)
	}
	if !p.advance() {
		t.Fatal("setup: the pool would not step onto the second edge")
	}
	if got, _, _ := p.current(); got != dead {
		t.Fatalf("setup: the step landed on %q, want the dead edge %q", got, dead)
	}

	if b.buildWarm("", true) {
		t.Fatal("a warm dial to a closed port reported success")
	}
	p.keepCursorOn(prevIP, prevSNI.host)

	p.mu.Lock()
	burned := !p.ipHealth.healthy(dead)
	liveStillOK := p.ipHealth.healthy(live)
	p.mu.Unlock()
	if !burned {
		t.Fatalf("%s refused the warm dial and was not burned — the next rotation walks straight back "+
			"onto it, and the panel keeps calling it healthy", dead)
	}
	if !liveStillOK {
		t.Fatalf("%s was burned for a failure on another edge", live)
	}
	if got, _, _ := p.current(); got != live {
		t.Fatalf("after the failed warm dial the pool sits on %q — the carrier is still on %q and the "+
			"status would name an edge nothing is using", got, live)
	}
	if p.advance() {
		t.Fatal("the next rotation stepped onto the edge it just burned; its backoff must hold it out")
	}
}
