package packet

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// settledEpoch waits until the carrier publishes a path with a session on it, and returns that epoch.
// It is the node's own gate: the node reads `ready` out of the status file and sends no verdict until
// it is set, so a test that stamps an epoch the carrier has not reached yet is testing a message the
// node would never have sent.
func settledEpoch(t *testing.T, s *coreStatus) int64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if e, _, ready := s.tracker.snapshot(); ready && e != 0 {
			return e
		}
		if time.Now().After(deadline) {
			t.Fatal("the carrier never published a live path")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// liveVerdict writes one verdict file the way the node does: into the TUNNEL's mailbox (never a pool's
// pin file), stamped with the epoch the carrier is publishing at that instant. Every test that drives a
// carrier through Run() has to go through this — a hand-written command with no epoch names a path the
// carrier is right to refuse, and hard-coding a number races the rotations the test is there to exercise.
func liveVerdict(t *testing.T, path string, epoch int64, c poolCmd) {
	t.Helper()
	c.Epoch = epoch
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	writeFileAtomic(path, data, 0o644)
}

// TestAStaleVerdictChangesNothingAndACurrentOneStillBurns.
//
// The node measures for most of a second and this poller reads on a one-second tick, so the path can
// move between the measurement and the verdict. One that names a path the carrier has already left
// must change nothing — acting on it charges that silence to whatever the tunnel moved onto, which is
// how a healthy destination gets condemned for a port roll it had no part in.
//
// Driven through pollPins rather than staleVerdict: a guard is only worth anything at the place the
// verdict is actually consumed, and that switch is where the mis-target lives.
func TestAStaleVerdictChangesNothingAndACurrentOneStillBurns(t *testing.T) {
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2"}, 0, filepath.Join(dir, "peerpool"))
	rc := newRotationController(dst, nil)
	rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	noop, rot := func() {}, func(bool) { dst.fail() }

	stale := int64(testPathEpoch - 1)
	liveVerdict(t, rc.verdict, stale, poolCmd{Cmd: cmdFail, Key: "d1"})
	rc.pollPins(noop, noop, rot, rot, nil, atPathEpoch)
	if burned := burnedIn(dst); len(burned) != 0 {
		t.Errorf("a verdict about epoch %d burned %v while the carrier is on %d", stale, burned, testPathEpoch)
	}

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdFail, Key: "d1"})
	rc.pollPins(noop, noop, rot, rot, nil, atPathEpoch)
	if burned := burnedIn(dst); !burned["d1"] {
		t.Error("a verdict on the LIVE path must still burn — the guard drops only the stale one")
	}
}

// TestEpochMovesForEveryFieldAndForNothingElse.
//
// The epoch is the whole guard: a verdict carrying a stale one is dropped, and one carrying the live
// one is acted on. So a field that can change the packet on the wire without moving the epoch is a
// verdict charged to a path it never measured — the exact misattribution this mechanism exists to
// stop. Field by field, not one sample, because a struct comparison that silently ignores a member is
// the way that guarantee rots.
func TestEpochMovesForEveryFieldAndForNothingElse(t *testing.T) {
	base := pathKey{Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 443, SNI: "a.example"}
	mutations := map[string]pathKey{
		"source ip":        {Src: "10.0.0.9", Sport: 41207, Dst: "10.0.0.2", Dport: 443, SNI: "a.example"},
		"source port":      {Src: "10.0.0.1", Sport: 41208, Dst: "10.0.0.2", Dport: 443, SNI: "a.example"},
		"destination ip":   {Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.9", Dport: 443, SNI: "a.example"},
		"destination port": {Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 8443, SNI: "a.example"},
		"sni":              {Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 443, SNI: "b.example"},
	}
	for name, moved := range mutations {
		var tr pathTracker
		tr.observe(base, true)
		before, _, _ := tr.snapshot()
		if !tr.observe(moved, true) {
			t.Errorf("%s changed but the tracker reported nothing to publish — the file would keep naming the old path", name)
		}
		after, got, _ := tr.snapshot()
		if after != before+1 {
			t.Errorf("%s: epoch %d -> %d, want exactly one step", name, before, after)
		}
		if got != moved {
			t.Errorf("%s: tracker published %+v, want %+v", name, got, moved)
		}
		if tr.observe(moved, true) {
			t.Errorf("%s: re-observing the same path spent an epoch", name)
		}
	}
}

// TestASessionComingUpIsPublishedThoughNoAddressMoved.
//
// Found by running it, not by reading it: a tunnel handshaked, started carrying, and the status file
// still said ready=false — because the flush was keyed on the PATH moving and a session coming up
// moves no address. The node gates every verdict on that flag, so the file froze at false and
// failover was dead for the life of the tunnel while the dashboard showed green.
//
// The epoch must NOT step for it: nothing about the path changed, and stepping would throw away the
// verdict measured either side of the handshake for no reason.
func TestASessionComingUpIsPublishedThoughNoAddressMoved(t *testing.T) {
	var tr pathTracker
	k := pathKey{Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 9000}
	tr.observe(k, false) // dialled, no session yet
	epoch, _, ready := tr.snapshot()
	if ready {
		t.Fatal("ready before any session")
	}

	if !tr.observe(k, true) {
		t.Error("the session came up and the tracker reported nothing to publish — the file keeps saying ready=false")
	}
	after, _, ready := tr.snapshot()
	if !ready {
		t.Error("ready never turned true")
	}
	if after != epoch {
		t.Errorf("epoch %d -> %d for a handshake — nothing about the path changed", epoch, after)
	}
}

// TestUnresolvedPathSpendsNoEpochAndIsNeverReady.
//
// A carrier mid-rebind, or one that has not learned its peer, has no path to name. Counting that as a
// move burns an epoch on a gap and throws away the verdict either side of it; carrying the previous
// `ready` through it is worse — it invites a verdict about a path the tunnel is not on.
func TestUnresolvedPathSpendsNoEpochAndIsNeverReady(t *testing.T) {
	var tr pathTracker
	live := pathKey{Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 443}
	tr.observe(live, true)
	epoch, _, ready := tr.snapshot()
	if !ready {
		t.Fatal("a carrier reporting an established session must publish ready")
	}
	if !tr.observe(pathKey{Src: "10.0.0.1", Sport: 41207}, true) {
		t.Error("losing the destination must be published — a reader still seeing ready would judge a path that is gone")
	}
	after, key, ready := tr.snapshot()
	if after != epoch {
		t.Errorf("epoch %d -> %d across an unresolved sample, want it held", epoch, after)
	}
	if key != live {
		t.Errorf("published path became %+v, want the last real one %+v", key, live)
	}
	if ready {
		t.Error("still ready while the carrier cannot name its destination")
	}
}
