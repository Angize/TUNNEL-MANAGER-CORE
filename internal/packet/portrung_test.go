package packet

import (
	"path/filepath"
	"testing"
)

func rungHarness(t *testing.T, withRung bool) (rc *rotationController, rolls *int, burns *int) {
	t.Helper()
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json"))
	rc = newRotationController(dst, src)
	rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	rolls, burns = new(int), new(int)
	if withRung {
		rc.port.setRoll(func() bool { *rolls++; return true }, nil)
	}
	return rc, rolls, burns
}

func (c *rotationController) failCounting(burns *int) {
	rot := func(bool) { *burns++ }
	c.fail(rot, rot)
}

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

func TestADrawThatDidNotMoveIsNotAStep(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)
	rc.port.setRoll(func() bool { *rolls++; return false }, nil)

	rc.failCounting(burns)
	if *burns == 0 {
		t.Error("a redraw that did not move must fall through to the walk in the same round")
	}
	if rc.port.spent != 0 {
		t.Errorf("a failed redraw spent %d of the budget", rc.port.spent)
	}
}

func TestTrafficCrossingRefillsTheDraws(t *testing.T) {
	rc, rolls, burns := rungHarness(t, true)
	rc.failCounting(burns)
	if *rolls != 1 {
		t.Fatalf("expected one draw spent, got %d", *rolls)
	}

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdOK, Key: rc.dst.current()})
	rc.pollPins(func() {}, func() {}, func(bool) {}, func(bool) {}, nil, atPathEpoch)

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
