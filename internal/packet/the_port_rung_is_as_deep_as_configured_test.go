package packet

import (
	"testing"
	"time"
)

func withPortTries(t *testing.T, n int) {
	t.Helper()
	old := portTries
	t.Cleanup(func() { portTries = old })
	SetPortTries(n)
	if portTries != n {
		t.Fatalf("SetPortTries(%d) left the budget at %d", n, portTries)
	}
}

func failOnce(t *testing.T, b *UDP, rc *rotationController) {
	t.Helper()
	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdFail, Low: low, High: high})
	rc.poll(b.rotatePeerUDP, b.rotateSourceUDP, nil, rc.st.pathEpoch)
}

// port_tries is the operator's say over the cheapest rung: how many times the carrier redraws its
// source port before anything more expensive happens. The panel only ever sent it for the raw carrier
// with a forged, rolling source port, so on a udp tunnel the core kept the compiled-in 2 whatever the
// operator set. Now that udp has a rung of its own the knob has to reach it, and the count has to be
// exactly what was asked -- the draws are what stands between a dead source port and a burned
// destination.
func TestTheUdpPortRungIsAsDeepAsConfigured(t *testing.T) {
	for _, want := range []int{1, 5} {
		withPortTries(t, want)
		b, rc := rigUDP(t, []string{"198.51.100.1:5555", "198.51.100.2:5555"})
		first := b.pp.current()
		seen := map[int]bool{udpSport(t, b): true}

		for i := 1; i <= want; i++ {
			failOnce(t, b, rc)
			if burned := burnedIn(b.pp); len(burned) != 0 {
				t.Fatalf("port_tries=%d: draw %d condemned %v", want, i, burned)
			}
			if got := b.pp.current(); got != first {
				t.Fatalf("port_tries=%d: draw %d walked the pool to %s", want, i, got)
			}
			p := udpSport(t, b)
			if seen[p] {
				t.Fatalf("port_tries=%d: verdict %d did not draw a new port (still %d)", want, i, p)
			}
			seen[p] = true
		}

		was := udpSport(t, b)
		failOnce(t, b, rc)
		if got := udpSport(t, b); got != was {
			t.Fatalf("port_tries=%d: verdict %d drew port %d — the budget is deeper than the operator set",
				want, want+1, got)
		}
	}
}

// When every rung is spent and the walk has nowhere to go, the ladder stops moving entirely. What
// starts it again is the revive clock -- the "wait before the ladder tries again" list in the panel's
// settings. It is one clock per controller and it was always there, but before udp had a port rung
// there was nothing for it to hand back on a udp tunnel: refilling gave the session drop and no more.
func TestTheReviveClockGivesTheUdpPortRungBack(t *testing.T) {
	t.Run("a source pool of one", func(t *testing.T) { reviveRound(t, true) })
	t.Run("no pools at all", func(t *testing.T) { reviveRound(t, false) })
}

func reviveRound(t *testing.T, withSrcPool bool) {
	oldRevive := ladderRevive
	t.Cleanup(func() { ladderRevive = oldRevive })
	ladderRevive = []int64{1}
	withPortTries(t, 1)

	b, _ := rigUDP(t, nil)
	if withSrcPool {
		b.SetSourcePool(NewPeerPool([]string{"127.0.0.1"}, 0))
	}
	rc := b.newController()
	start := udpSport(t, b)

	failOnce(t, b, rc)
	drawn := udpSport(t, b)
	if drawn == start {
		t.Fatal("the first verdict did not spend the port rung")
	}

	failOnce(t, b, rc)
	failOnce(t, b, rc)
	if got := udpSport(t, b); got != drawn {
		t.Fatalf("the ladder kept drawing ports past its budget: %d", got)
	}

	time.Sleep(1200 * time.Millisecond)
	failOnce(t, b, rc)
	failOnce(t, b, rc)
	if got := udpSport(t, b); got == drawn {
		t.Fatalf("the revive clock elapsed and the port rung was never handed back — the tunnel is on "+
			"port %d for good, and the only cheap repair it has is spent", got)
	}
}
