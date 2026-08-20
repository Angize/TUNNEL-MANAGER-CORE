package packet

import "testing"

func TestCondemnedIsOnlyARealBurn(t *testing.T) {
	pool := NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0)
	c := newRotationController(pool, nil)
	rot := func(proactive bool) { pool.nextEndpoint(proactive) }

	if !c.fail(rot, nil) {
		t.Fatal("a healthy endpoint was burned, so the verdict WAS charged: fail() reported otherwise")
	}
	if !c.fail(rot, nil) {
		t.Fatal("the second healthy endpoint was burned too: fail() reported otherwise")
	}
	if c.fail(rot, nil) {
		t.Error("every endpoint is already burned and none is due for retest, so healthSet.burn is a " +
			"no-op and nothing was charged. Reporting a burn here makes judge() emit one burn event " +
			"per verdict for as long as the outage lasts")
	}

	single := NewPeerPool([]string{"10.0.0.9"}, 0)
	if newRotationController(single, nil).fail(func(bool) { single.nextEndpoint(false) }, nil) {
		t.Error("a one-entry pool refuses to burn, so no endpoint was charged")
	}
}
