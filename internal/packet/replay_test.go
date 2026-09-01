package packet

import "testing"

func TestReplayGuardBasics(t *testing.T) {
	var g replayGuard
	if !g.ok(1, 1) {
		t.Fatal("first frame must be accepted")
	}
	if g.ok(1, 1) {
		t.Fatal("exact duplicate must be rejected")
	}
	if !g.ok(1, 2) {
		t.Fatal("next in-order frame must be accepted")
	}
	if !g.ok(1, 5) {
		t.Fatal("forward jump must be accepted")
	}
	if !g.ok(1, 3) {
		t.Fatal("in-window out-of-order frame must be accepted once")
	}
	if g.ok(1, 3) {
		t.Fatal("replay of an in-window frame must be rejected")
	}
	if g.ok(1, 5) {
		t.Fatal("replay of the current top must be rejected")
	}
}

func TestReplayGuardTooOld(t *testing.T) {
	var g replayGuard
	const top = replayWindow * 2
	g.ok(1, top)
	if g.ok(1, top-replayWindow) {
		t.Fatal("a frame exactly a window behind the newest must be rejected")
	}
	if !g.ok(1, top-replayWindow+1) {
		t.Fatal("a frame just inside the window must be accepted")
	}
	if !g.ok(1, top-1) {
		t.Fatal("a frame one behind the newest must be accepted")
	}
}

func TestReplayGuardSessionReset(t *testing.T) {
	var g replayGuard
	g.ok(7, 500)

	if !g.ok(8, 1) {
		t.Fatal("a new session must adopt and accept, enabling reconnect")
	}
	if g.ok(8, 1) {
		t.Fatal("duplicate under the new session must still be rejected")
	}
}

func TestReplayGuardFarForwardShift(t *testing.T) {
	var g replayGuard
	g.ok(1, 1)
	if !g.ok(1, 1_000_000) {
		t.Fatal("a large forward jump must be accepted")
	}
	if g.ok(1, 1) {
		t.Fatal("an ancient frame after a big jump must be rejected")
	}
}
