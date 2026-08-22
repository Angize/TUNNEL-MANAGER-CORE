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

	// A one-entry pool has nowhere to go but still records the burn, so the FIRST verdict is charged.
	single := NewPeerPool([]string{"10.0.0.9"}, 0)
	sc := newRotationController(single, nil)
	rotOne := func(bool) { single.nextEndpoint(false) }
	if !sc.fail(rotOne, nil) {
		t.Error("a one-entry pool left its only endpoint green; nothing rotates away from it, but the " +
			"panel then calls it healthy while the tunnel carries nothing")
	}
	if sc.fail(rotOne, nil) {
		t.Error("and the SECOND verdict was charged again — the backoff it already stamped has not " +
			"elapsed, so this is one burn, not one event per sweep")
	}
}
