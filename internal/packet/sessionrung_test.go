package packet

import (
	"path/filepath"
	"testing"
)

func rungLadder(t *testing.T) (rc *rotationController, rolls, drops, burns *int) {
	t.Helper()
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, 0)
	src := NewPeerPool([]string{"s1", "s2"}, 0)
	rc = newRotationController(dst, src)
	rc.attachStatus(newCoreStatus(filepath.Join(dir, "core.json"), ""))
	rolls, drops, burns = new(int), new(int), new(int)
	rc.port.setRoll(func() bool { *rolls++; return true })
	rc.session.setDrop(func() bool { *drops++; return true })
	return rc, rolls, drops, burns
}

func TestTheLadderSpendsItsFreeStepsInOrder(t *testing.T) {
	rc, rolls, drops, burns := rungLadder(t)
	rot := func(bool) { *burns++ }

	for i := 1; i <= portTries; i++ {
		rc.fail(rot, rot)
		if *drops != 0 || *burns != 0 {
			t.Fatalf("verdict %d: the redraws must be spent first, got drops=%d burns=%d", i, *drops, *burns)
		}
	}

	rc.fail(rot, rot)
	if *drops != 1 {
		t.Errorf("with the redraws spent the next verdict must handshake again, got drops=%d", *drops)
	}
	if *burns != 0 {
		t.Error("the handshake costs nothing and blames nobody, so nothing may be condemned for it")
	}

	rc.fail(rot, rot)
	if *burns == 0 {
		t.Error("every free step is spent — the walk must take over, or a dead endpoint is never left")
	}
	if *rolls != portTries || *drops != 1 {
		t.Errorf("the ladder kept spending past its budget: rolls=%d drops=%d", *rolls, *drops)
	}
}

func TestTheHandshakeIsSpentOncePerOutage(t *testing.T) {
	rc, _, drops, burns := rungLadder(t)
	rot := func(bool) { *burns++ }

	for i := 0; i < portTries+4; i++ {
		rc.fail(rot, rot)
	}
	if *drops != 1 {
		t.Errorf("the handshake was spent %d times in one outage, want once", *drops)
	}
}

func TestAHandshakeAlreadyInFlightIsNotAStep(t *testing.T) {
	rc, _, drops, burns := rungLadder(t)
	rc.session.setDrop(func() bool { *drops++; return false })
	rot := func(bool) { *burns++ }

	for i := 1; i <= portTries; i++ {
		rc.fail(rot, rot)
	}
	rc.fail(rot, rot)
	if *burns == 0 {
		t.Error("a handshake that could not be given up must fall through to the walk in the same round")
	}
	if rc.session.spent {
		t.Error("a step that did not happen was still marked spent")
	}
}

func TestTrafficCrossingRefillsBothRungs(t *testing.T) {
	rc, rolls, drops, burns := rungLadder(t)
	rot := func(bool) { *burns++ }

	for i := 0; i < portTries+1; i++ {
		rc.fail(rot, rot)
	}
	if *burns != 0 {
		t.Fatalf("setup: nothing should have burned yet, got %d", *burns)
	}

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdOK, Low: rc.dst.current(), High: rc.src.current()})
	rc.poll(func(bool) {}, func(bool) {}, nil, atPathEpoch)

	for i := 1; i <= portTries+1; i++ {
		rc.fail(rot, rot)
	}
	if *burns != 0 {
		t.Error("the fresh outage condemned an endpoint: it inherited the last one's spent budget")
	}
	if *rolls != 2*portTries || *drops != 2 {
		t.Errorf("after the refill: rolls=%d drops=%d, want %d and 2", *rolls, *drops, 2*portTries)
	}
}

func TestAPinnedTunnelStillHandshakesAndKeepsItsAllowance(t *testing.T) {
	rc, _, drops, burns := rungLadder(t)
	rot := func(bool) { *burns++ }
	if !rc.dst.selectEntry("d2") {
		t.Fatal("could not pin")
	}

	for i := 1; i <= portTries+1; i++ {
		rc.fail(rot, rot)
	}
	if *drops != 1 {
		t.Errorf("a pinned tunnel refused to handshake again (drops=%d)", *drops)
	}
	if !rc.dst.isPinned() {
		t.Error("the pin was released by rounds that only redrew and re-handshaked — both are free and " +
			"blame nobody, so neither is a second opinion about the operator's pick")
	}
}
