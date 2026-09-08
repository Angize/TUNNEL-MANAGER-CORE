//go:build linux

package packet

import (
	"encoding/json"
	"os"
	"testing"
)

// The node's decision, modelled from tnl-node.py so this test asks the question the operator asks:
//
//	settle():        crossed -> pub=True, bad=0
//	                 else    -> bad++; if not (pub is True and bad < RED_SWEEPS): pub=False
//	pool_failover(): counted = stable and not crossed
//	                 crossed -> onbad = 0; else if counted and the same pair -> onbad++
//	                 a fail verdict is written only when alive is False, the sweep counted,
//	                 and onbad >= RED_SWEEPS
const redSweeps = 2

type nodeSweeper struct {
	pub     int
	bad     int
	on      string
	onbad   int
	verdict int
}

func (n *nodeSweeper) sweep(t *testing.T, r *poolRig, crossed, stable bool) {
	t.Helper()
	if crossed {
		n.pub, n.bad = 1, 0
	} else {
		n.bad++
		if !(n.pub == 1 && n.bad < redSweeps) {
			n.pub = -1
		}
	}
	low, high := r.live()
	counted := stable && !crossed
	if crossed {
		n.on, n.onbad = "", 0
	} else if counted {
		if n.on != low+"|"+high {
			n.on, n.onbad = low+"|"+high, 0
		}
		n.onbad++
	}
	if n.pub != -1 || !counted || n.onbad < redSweeps {
		return
	}
	n.verdict++
	data, err := json.Marshal(poolCmd{Cmd: cmdFail, Low: low, High: high, Epoch: r.st.pathEpoch()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.st.verdictPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}
	r.poll()
}

// Measured in production and recorded on TestTheFirstVerdictAboutThePairTheWalkArrivedOnSpendsNothing:
// a ws tunnel with three CDN edges, 185 genuinely dead, the ladder condemned it and arrived on 104 --
// and 104, which nothing had faulted, was condemned six seconds later. The rung spent on the first
// verdict about 104 closed the connection that had come up two seconds earlier, and the verdict after
// it measured the gap the core had just made.
//
// So: the first destination is dead, the second carries. Does the second get condemned too, on any
// carrier?
//
// The ladder's own port rung closes the carrier, so the sweep after a rung opens in the dark and reads
// "nothing crossed". Whether the node discards that sweep depends on the gap. A gap that ends inside
// the 0.8s probe window is a path change and the node throws the sweep away; one that OUTLIVES the
// window is invisible to it, because pathTracker.observe does not move the epoch while there is no
// live path at all. Measured on DE02 with netem: the gap runs about 3x RTT, so it outlives the window
// above roughly 260ms RTT. Both regimes are driven here, and neither may condemn the healthy edge.
func TestNoCarrierCondemnsAnEndpointThatIsCarrying(t *testing.T) {
	for _, tc := range []struct {
		name        string
		gapOutlives bool
		darkSweeps  int
	}{
		{"the gap ends inside the probe window", false, 1},
		{"the gap outlives the probe window", true, 1},
		{"the gap outlives a whole sweep", true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eachCarrier(t, func(t *testing.T, r *poolRig) {
				dead, healthy := rigDsts[0], rigDsts[1]
				// Every carrier teardown darkens the sweeps that follow it: the port rung closes the
				// connection, and so does the drop that commits a walk. How MANY it darkens is how the
				// reconnect compares with the node's sweep interval.
				dark := 0
				r.rc.port.setRoll(func() bool { dark = tc.darkSweeps; return true })
				was, _ := r.live()

				n := &nodeSweeper{}
				for i := 0; i < 300; i++ {
					low, _ := r.live()
					if low != was {
						dark, was = tc.darkSweeps, low
					}
					blind := dark > 0
					if dark > 0 {
						dark--
					}
					n.sweep(t, r, low == healthy && !blind, !blind || tc.gapOutlives)
				}

				if n.verdict == 0 {
					t.Fatalf("%s: the node never wrote a verdict, so nothing was exercised", r.name)
				}
				if !burned(r.low, dead) {
					t.Fatalf("%s: the dead endpoint %q was never condemned -- this test would pass on a "+
						"ladder that does nothing at all", r.name, dead)
				}
				if burned(r.low, healthy) {
					t.Fatalf("%s: %q was condemned, and it was carrying every sweep the ladder did not "+
						"darken itself -- the core blamed an endpoint for a gap the core made",
						r.name, healthy)
				}
				if now, _ := r.live(); now != healthy {
					t.Fatalf("%s: the pool ended on %q, not on the one that carries", r.name, now)
				}
			})
		})
	}
}
