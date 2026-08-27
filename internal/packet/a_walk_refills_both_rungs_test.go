package packet

import (
	"path/filepath"
	"testing"
)

// A tunnel that only varies its SOURCE. The walk turns that axis, and turning it keeps the session --
// so unlike a destination move, nothing else puts a handshake on the wire afterwards. This is the
// shape where a spent session rung is the difference between recovering and not.
func srcOnlyLadder(t *testing.T) (rc *rotationController, src *PeerPool, rolls, drops *int) {
	t.Helper()
	src = NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	rc = newRotationController(nil, src)
	rolls, drops = new(int), new(int)
	rc.port.setRoll(func() bool { *rolls++; return true })
	rc.session.setDrop(func() bool { *drops++; return true })
	rc.attachStatus(newCoreStatus(filepath.Join(t.TempDir(), "core.status"), ""))
	return rc, src, rolls, drops
}

// One verdict, naming the pair the carrier is on right now -- which is what the node's probe writes,
// and what the ladder refuses to spend a rung on if it names anywhere else.
func failLivePair(t *testing.T, rc *rotationController, rot func(bool)) {
	t.Helper()
	low, high := rc.livePair()
	liveVerdict(t, rc.verdict, rc.st.pathEpoch(), poolCmd{Cmd: cmdFail, Low: low, High: high})
	rc.poll(func(bool) {}, rot, nil, rc.st.pathEpoch)
}

// The free rungs are the ladder's answer for a place it has not judged yet, and a walk arrives
// somewhere new. Both of them come back, or the second endpoint gets a shorter ladder than the first
// for no reason -- and on a source-only tunnel the handshake is the ONLY rung that can bring a dead
// session back, because turning the source axis keeps it and sends nothing.
func TestAWalkRefillsBothFreeRungs(t *testing.T) {
	rc, src, rolls, drops := srcOnlyLadder(t)
	rot := func(bool) { src.fail("tun-probe") }

	spendTheLadder := func() {
		t.Helper()
		for i := 0; i <= portTries+1; i++ { // the draws, the handshake, then the walk
			failLivePair(t, rc, rot)
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
		t.Errorf("the walk refilled the port draws but not the handshake: %d in total, want 2. The "+
			"session rung is then spent for the rest of the tunnel's life, and a source-only tunnel "+
			"has nothing else that can ask for a new key", *drops)
	}
}
