package packet

import (
	"net"
	"path/filepath"
	"testing"
)

// A refused dial condemns nothing on its own -- the tun probe is the one judge, on the edge pool
// exactly as on a direct carrier. What the dial must do is STAY: the pool holds its combination while
// the reconnect backoff paces the retries, so the endpoint the probe measures is still the endpoint
// the verdict will name. Stepping here would make that name change under it every retry.
func TestARefusedDialCondemnsNothingAndStaysPut(t *testing.T) {
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
	for i := 0; i < 3; i++ {
		if _, _, _, err := b.dialCarrier(); err == nil {
			t.Fatal("setup: the dial to a closed port succeeded")
		}
	}

	p.mu.Lock()
	burned := len(p.ipHealth.recs) + len(p.sniHealth.recs)
	p.mu.Unlock()
	if burned != 0 {
		t.Errorf("three refused dials condemned %d entr(ies). The dial is not the judge here; the tun "+
			"probe is, and it is the only thing that can tell a filtered edge from a broken one", burned)
	}
	if got, _, _ := p.current(); got != dead {
		t.Errorf("the pool stepped to %q while retrying %q. The status then names a different edge on "+
			"every attempt, and the verdict that arrives cannot be charged to what it measured", got, dead)
	}
}

// ...and the slow path still gets there: the probe names the edge the carrier is stuck on, and the
// ladder condemns it once the free rungs are spent.
func TestTheProbeStillCondemnsTheEdgeTheDialCouldNotReach(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("x"))
	b := &TCP{isClient: true, ws: true, wsPath: "/", pool: p, closeCh: make(chan struct{})}
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	b.rc.port.setRoll(func() bool { return true })

	b.noteAttempt("e1", "x") // what the failing dial published
	for i := 0; i <= portTries; i++ {
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ipHealth.healthy("e1") {
		t.Error("the edge the dial could not reach was never condemned. Removing the dial burn only " +
			"moves the evidence to the probe; it must not lose it")
	}
}

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
