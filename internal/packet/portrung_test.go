package packet

import (
	"path/filepath"
	"testing"
)

// rungHarness builds a real controller with both pools and a rung whose redraw is counted rather than
// performed, so a test can watch the ORDER the ladder spends its steps in.
func rungHarness(t *testing.T, withRung bool) (rc *rotationController, rolls *int, burns *int) {
	t.Helper()
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json"))
	rc = newRotationController(dst, src)
	rolls, burns = new(int), new(int)
	if withRung {
		rc.port.setRoll(func() bool { *rolls++; return true })
	}
	return rc, rolls, burns
}

func (c *rotationController) failCounting(burns *int) {
	rot := func(bool) { *burns++ }
	c.fail(rot, rot)
}

// TestNothingIsCondemnedWhileTheCheapStepRemains.
//
// The blocking this exists for is keyed on (destination, source port), so a tunnel dies with no
// endpoint at fault. A walk that starts at the destination answers by burning a healthy server — and
// the port that actually did it gets redrawn minutes later on an unrelated schedule, which reads as
// the destination change having worked. So every free draw is spent before anything is condemned.
func TestNothingIsCondemnedWhileTheCheapStepRemains(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)

	for i := 1; i <= portTries; i++ {
		rc.failCounting(burns)
		if *burns != 0 {
			t.Fatalf("verdict %d of %d condemned an endpoint while a free redraw was still available", i, portTries)
		}
		if *rolls != i {
			t.Fatalf("verdict %d spent %d redraws, want %d", i, *rolls, i)
		}
	}

	rc.failCounting(burns)
	if *rolls != portTries {
		t.Errorf("the rung kept drawing past its budget: %d draws for %d tries", *rolls, portTries)
	}
	if *burns == 0 {
		t.Error("with the port axis spent the walk must take over — otherwise a genuinely dead " +
			"destination is never left")
	}
}

// TestACarrierWithNoPortAxisWalksImmediately.
//
// A profile that forges no port, or a carrier whose ports are derived rather than chosen, has no rung
// zero. It must behave exactly as it did before this existed — the axis it does not have cannot delay
// the one it does.
func TestACarrierWithNoPortAxisWalksImmediately(t *testing.T) {
	rc, rolls, burns := rungHarness(t, false)
	rc.failCounting(burns)
	if *rolls != 0 {
		t.Fatalf("a carrier with no rung redrew %d times", *rolls)
	}
	if *burns == 0 {
		t.Error("the first verdict must reach the walk when there is no cheaper step to take")
	}
}

// TestADrawThatDidNotMoveIsNotAStep.
//
// The redraw can fail — the random source runs dry, or the profile turns out to forge no port after
// all. Counting that as a step would spend the budget on nothing and delay the walk for a rung that
// never actually moved the tunnel.
func TestADrawThatDidNotMoveIsNotAStep(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)
	rc.port.setRoll(func() bool { *rolls++; return false })

	rc.failCounting(burns)
	if *burns == 0 {
		t.Error("a redraw that did not move must fall through to the walk in the same round")
	}
	if rc.port.spent != 0 {
		t.Errorf("a failed redraw spent %d of the budget", rc.port.spent)
	}
}

// TestTrafficCrossingRefillsTheDraws.
//
// The budget is per OUTAGE. A tunnel that came back settles the question this rung was asking, so the
// next one starts with the full allowance rather than the remainder of the last.
func TestTrafficCrossingRefillsTheDraws(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)
	rc.failCounting(burns)
	if *rolls != 1 {
		t.Fatalf("expected one draw spent, got %d", *rolls)
	}

	rc.success() // the carrier is answering again

	for i := 1; i <= portTries; i++ {
		rc.failCounting(burns)
	}
	if *burns != 0 {
		t.Errorf("the fresh outage condemned an endpoint after %d draws — it inherited the last one's "+
			"spent budget instead of a full one", *rolls)
	}
	if *rolls != 1+portTries {
		t.Errorf("draws after the refill: %d, want %d", *rolls-1, portTries)
	}
}

// TestAPinnedTunnelStillRedrawsAndKeepsItsAllowance.
//
// A pin says "stay on this endpoint". A redraw does exactly that — it moves nothing — so it is the one
// step that is always compatible with the operator's pick, and a round spent on it is no evidence
// against the pinned endpoint. Spending the pin's allowance on it would break the pick on measurements
// that never tested it.
func TestAPinnedTunnelStillRedrawsAndKeepsItsAllowance(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)
	if !rc.dst.selectEntry("d2") {
		t.Fatal("could not pin")
	}

	rc.failCounting(burns)
	if *rolls != 1 {
		t.Errorf("a pinned tunnel refused the one step that keeps it on its pick (%d draws)", *rolls)
	}
	if !rc.dst.isPinned() {
		t.Error("the pin was released by a round that only redrew a port")
	}
	if rc.pinFails != 0 {
		t.Errorf("the pin's allowance was spent on a port redraw (pinFails=%d)", rc.pinFails)
	}
}
