package packet

import "testing"

// A burn used to be reported only the FIRST time an endpoint was condemned. Once a record existed, every
// later burn was silent: no ring event, no burnCount, and no reassessRotation -- so walk() read
// lowBurned as false and the operator's card never moved.
//
// Measured live on core13: the rotation landed on 185.143.23.238 after its retest came due, the node
// asked four times to fail it, the core logged "the ladder walked off it" twice, and the ring showed no
// burn at all. The operator sees a rotation and concludes the burn did not happen.
//
// A repeat inside the backoff window is still silent -- that endpoint is already condemned and nothing
// changed. What must be reported is a re-condemnation: the retest had come due, so the endpoint was
// usable again, and this burn takes it back out.
func TestAnEndpointCondemnedAgainAfterItsRetestIsBurnedAgain(t *testing.T) {
	p := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0)
	clk := int64(1_000_000)
	p.now = func() int64 { return clk }

	var burns []string
	p.attach("dst", func(kind, _, detail string) {
		if kind == "burn" {
			burns = append(burns, detail)
		}
	}, func() {})

	p.fail("tun-probe")
	if len(burns) != 1 || p.burnCount() != 1 {
		t.Fatalf("setup: the first burn must be reported, got %d event(s) and burnCount %d",
			len(burns), p.burnCount())
	}

	p.keepCursorOn("10.0.0.1")
	p.fail("tun-probe")
	if len(burns) != 1 || p.burnCount() != 1 {
		t.Errorf("a repeat inside the backoff window must stay silent: %d event(s), burnCount %d -- the "+
			"endpoint is already condemned and nothing changed", len(burns), p.burnCount())
	}

	clk += suspectBackoff[0] + 1
	p.keepCursorOn("10.0.0.1")
	p.fail("tun-probe")
	if len(burns) != 2 || p.burnCount() != 2 {
		t.Errorf("once its retest came due the endpoint was usable again, so condemning it is news: "+
			"%d event(s), burnCount %d, want 2 and 2", len(burns), p.burnCount())
	}
}

// The backoff has to walk on too, or the endpoint circles between suspect and retest for the life of the
// process and never reaches dead. Live on core13 it sat at fails=0 after being burned repeatedly.
func TestEachRecondemnationWalksTheBackoffOn(t *testing.T) {
	p := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0)
	clk := int64(1_000_000)
	p.now = func() int64 { return clk }
	p.attach("dst", func(string, string, string) {}, func() {})

	seen := []int{}
	p.fail("tun-probe")
	for i := 0; i < len(suspectBackoff)+1; i++ {
		rows := p.healthRows()
		for _, r := range rows {
			if r.Key == "10.0.0.1" {
				seen = append(seen, r.Fails)
			}
		}
		clk = 0
		for _, r := range p.healthRows() {
			if r.Key == "10.0.0.1" && r.NextRetest > clk {
				clk = r.NextRetest + 1
			}
		}
		p.keepCursorOn("10.0.0.1")
		p.fail("tun-probe")
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] && seen[i] < len(suspectBackoff) {
			t.Errorf("the failure count stalled at %v -- an endpoint that keeps failing must reach dead, "+
				"not circle between suspect and retest forever", seen)
			break
		}
	}
}
