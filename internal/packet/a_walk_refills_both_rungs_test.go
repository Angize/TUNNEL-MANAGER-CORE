package packet

import (
	"path/filepath"
	"testing"
)

// One ladder, whichever axis the test wants to vary, with the two free rungs counted.
func ladderOn(t *testing.T, dst, src *PeerPool) (rc *rotationController, rolls, drops *int) {
	t.Helper()
	rc = newRotationController(dst, src)
	rolls, drops = new(int), new(int)
	rc.port.setRoll(func() bool { *rolls++; return true })
	rc.session.setDrop(func() bool { *drops++; return true })
	rc.attachStatus(newCoreStatus(filepath.Join(t.TempDir(), "core.status"), ""))
	return rc, rolls, drops
}

// One verdict, naming the pair the carrier is on right now -- which is what the node's probe writes,
// and what the ladder refuses to spend a rung on if it names anywhere else.
func failLivePair(t *testing.T, rc *rotationController, rotLow, rotHigh func(bool)) {
	t.Helper()
	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdFail, Low: low, High: high})
	rc.poll(rotLow, rotHigh, nil, rc.st.pathEpoch)
}

func noRot(bool) {}

// The ladder every raw client on the fleet actually has: no destination pool, and a source pool of
// ONE, which main.go builds from bind_ip whenever src_ips is empty. That pool has nowhere to go, so
// it declines every rotation and the tunnel never leaves the place it started.
//
// Nothing may hand the free rungs back there. A ladder that does redraws the forged source port every
// few seconds for the life of the process, and a raw/tcp client that opens a brand new forged flow
// that often is not a tunnel a stateful path will carry -- so the probe keeps failing, which is what
// makes it redraw again.
func TestAPoolOfOneNeverRefillsTheLadder(t *testing.T) {
	src := NewPeerPool([]string{"94.182.131.47"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.nextEndpoint(false) } // what rotateSourceRaw does: ask, be declined, return

	for i := 0; i < 60; i++ { // a minute of the node's probe
		failLivePair(t, rc, noRot, rot)
	}
	if *rolls > portTries {
		t.Errorf("%d source-port draws in 60 verdicts; the ladder has %d, and a pool of one gives it "+
			"nowhere to arrive, so nothing may hand them back", *rolls, portTries)
	}
	if *drops > 1 {
		t.Errorf("%d re-handshakes in 60 verdicts; the ladder has 1", *drops)
	}
}

// The same on the digit a fail CONDEMNS. Burning the only entry is not arriving anywhere either: the
// cursor has nowhere to advance to, and the tunnel is still sitting on what was just burned.
func TestBurningTheOnlyDestinationIsNotAWalk(t *testing.T) {
	dst := NewPeerPool([]string{"10.0.0.1"}, 0)
	rc, rolls, drops := ladderOn(t, dst, nil)
	rot := func(bool) { dst.fail("tun-probe") }

	for i := 0; i < 40; i++ {
		failLivePair(t, rc, rot, noRot)
	}
	if *rolls > portTries || *drops > 1 {
		t.Errorf("a one-entry destination pool got %d draws and %d re-handshakes in 40 verdicts, want "+
			"at most %d and 1", *rolls, *drops, portTries)
	}
}

// ...and when the walk really does arrive somewhere, both rungs come back. Otherwise the second
// endpoint climbs a shorter ladder than the first for no reason anyone chose -- and on a source-only
// tunnel the handshake is the ONLY rung that can replace a dead session, because turning the source
// axis keeps it and sends nothing.
func TestAWalkRefillsBothFreeRungs(t *testing.T) {
	src := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	rc, rolls, drops := ladderOn(t, nil, src)
	rot := func(bool) { src.fail("tun-probe") }

	spendTheLadder := func() {
		t.Helper()
		for i := 0; i <= portTries+1; i++ { // the draws, the handshake, then the walk
			failLivePair(t, rc, noRot, rot)
		}
	}

	was := src.current()
	spendTheLadder()
	if src.current() == was {
		t.Fatalf("setup: the ladder never walked off %s, so nothing here is about a refill", was)
	}
	if *rolls != portTries || *drops != 1 {
		t.Fatalf("the first climb spent %d draw(s) and %d handshake(s), want %d and 1",
			*rolls, *drops, portTries)
	}

	spendTheLadder()
	if *rolls != 2*portTries {
		t.Errorf("the second climb drew the source port %d time(s) in total, want %d", *rolls, 2*portTries)
	}
	if *drops != 2 {
		t.Errorf("the walk arrived somewhere new and handed back the port draws but not the handshake: "+
			"%d in total, want 2", *drops)
	}
}

// The operator's number for THIS tunnel, honoured by the rung itself and not merely stored. A tunnel
// with one destination and one source has nothing after these draws and a re-handshake, so this is its
// whole recovery budget -- and how long a path is worth trying belongs to the path, not to the fleet.
func TestTheDrawBudgetIsTheOperatorsNumber(t *testing.T) {
	was := portTries
	t.Cleanup(func() { portTries = was })

	for _, want := range []int{1, 5, 12} {
		portTries = was
		SetPortTries(want)
		if portTries != want {
			t.Fatalf("SetPortTries(%d) left portTries=%d", want, portTries)
		}
		src := NewPeerPool([]string{"94.182.131.47"}, 0)
		rc, rolls, drops := ladderOn(t, nil, src)
		rot := func(bool) { src.nextEndpoint(false) }
		for i := 0; i < 3*want+20; i++ {
			failLivePair(t, rc, noRot, rot)
		}
		if *rolls != want {
			t.Errorf("port_tries=%d: the rung drew %d time(s), want exactly %d", want, *rolls, want)
		}
		if *drops != 1 {
			t.Errorf("port_tries=%d: %d re-handshakes, want 1 — the handshake rung is not the knob", want, *drops)
		}
	}
}

// 0 means "leave it alone", and the ceiling is the panel's.
func TestTheDrawBudgetIsClamped(t *testing.T) {
	was := portTries
	t.Cleanup(func() { portTries = was })
	for _, tc := range []struct {
		in, want int
	}{{0, was}, {-3, was}, {1, 1}, {50, 50}, {999, 50}} {
		portTries = was
		SetPortTries(tc.in)
		if portTries != tc.want {
			t.Errorf("SetPortTries(%d) -> %d, want %d", tc.in, portTries, tc.want)
		}
	}
}
