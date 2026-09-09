package packet

import (
	"net"
	"testing"
)

// A refused dial condemns nothing on its own -- the tun probe is the one judge, on the edge pools
// exactly as on a direct carrier. What the dial must do is STAY: the pools hold their combination while
// the reconnect backoff paces the retries, so the endpoint the probe measures is still the endpoint
// the verdict will name. Stepping here would make that name change under it every retry.
func TestARefusedDialCondemnsNothingAndStaysPut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close() // nothing listens there any more: connect refused

	b, pp, sp := edgeCarrier(t, []string{dead, "127.0.0.2:1"}, snis("x"))

	if ip := pp.current(); ip != dead {
		t.Fatalf("setup: the edge pool starts on %q, want %q", ip, dead)
	}
	for i := 0; i < 3; i++ {
		if _, _, _, err := b.dialCarrier(); err == nil {
			t.Fatal("setup: the dial to a closed port succeeded")
		}
	}

	pp.mu.Lock()
	burned := len(pp.health.recs)
	pp.mu.Unlock()
	sp.mu.Lock()
	burned += len(sp.health.recs)
	sp.mu.Unlock()
	if burned != 0 {
		t.Errorf("three refused dials condemned %d entr(ies). The dial is not the judge here; the tun "+
			"probe is, and it is the only thing that can tell a filtered edge from a broken one", burned)
	}
	if got := pp.current(); got != dead {
		t.Errorf("the edge pool stepped to %q while retrying %q. The status then names a different edge on "+
			"every attempt, and the verdict that arrives cannot be charged to what it measured", got, dead)
	}
}

// ...and the slow path still gets there: the probe names the edge the carrier is stuck on, and the
// ladder condemns it once the free rungs are spent. The burn now happens inside the edge pool's own
// fail(), on the walk itself, so nothing in front of the walk has to remember what was measured.
func TestTheProbeStillCondemnsTheEdgeTheDialCouldNotReach(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"e1", "e2"}, snis("x"))
	b.rc.port.setRoll(func() bool { return true })

	b.noteAttempt("e1", "x") // what the failing dial published
	for i := 0; i <= portTries; i++ {
		low, high := b.livePairNow()
		b.rc.judge(poolCmd{Cmd: cmdFail, Low: low, High: high}, b.rotateLowTCP, b.rotateHighTCP, 0)
	}

	pp.mu.Lock()
	defer pp.mu.Unlock()
	if pp.health.healthy("e1") {
		t.Error("the edge the dial could not reach was never condemned. Removing the dial burn only " +
			"moves the evidence to the probe; it must not lose it")
	}
}

// A verdict for a combination the pools have already left burns the half the WALK varied, because that
// is the half whose change makes the pair stale. With two edges the walk steps the edge; with one edge
// the low axis cannot step, the walk carries the domain instead, and the domain is what answers for it.
func TestAStaleComboVerdictBurnsTheAxisTheWalkVaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ips   []string
		burnt string // "sni" or "ip"
	}{
		{"two edges: the walk steps the edge, so the edge takes it", []string{"e1", "e2"}, "ip"},
		{"one edge: only the domain could step, so the domain takes it", []string{"only"}, "sni"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, pp, sp := edgeCarrier(t, tc.ips, snis("s1", "s2"))

			measIP, measSNI, ok := b.edgeCombo()
			if !ok {
				t.Fatal("setup: the edge pools have no combination")
			}
			b.pretendConnected(measIP, measSNI.host)
			if !b.stepEdge() {
				t.Fatal("setup: the pools would not move")
			}

			// The carrier is DOWN, so the published pair follows the cursors -- which is exactly the
			// window this arm exists for: the probe measured the pair we have just left.
			b.pretendDown()
			b.tunFail(t, measIP, measSNI.host)

			pp.mu.Lock()
			ipBurned := !pp.health.healthy(measIP)
			pp.mu.Unlock()
			sp.mu.Lock()
			sniBurned := !sp.health.healthy(measSNI.host)
			sp.mu.Unlock()

			if tc.burnt == "ip" && (!ipBurned || sniBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with a second edge the walk stepped the edge, and the "+
					"edge is what a failed combination condemns; convicting the domain here loses it on "+
					"every edge at once", sniBurned, ipBurned)
			}
			if tc.burnt == "sni" && (!sniBurned || ipBurned) {
				t.Fatalf("sniBurned=%v ipBurned=%v — with one edge the walk could only carry the domain, "+
					"and charging the edge takes the only one the tunnel has", sniBurned, ipBurned)
			}
		})
	}
}
