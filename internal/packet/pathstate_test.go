package packet

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

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

func liveVerdict(t *testing.T, path string, epoch int64, c poolCmd) {
	t.Helper()
	c.Epoch = epoch
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	writeFileAtomic(path, data, 0o644)
}

func TestAStaleVerdictChangesNothingAndACurrentOneStillBurns(t *testing.T) {
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2"}, 0)
	rc := newRotationController(dst, nil)
	rc.attachStatus(newCoreStatus(filepath.Join(dir, "core.json"), ""))
	rot := func(bool) { dst.fail("tun-probe") }

	stale := int64(testPathEpoch - 1)
	liveVerdict(t, rc.verdict, stale, poolCmd{Cmd: cmdFail, Low: "d1"})
	rc.poll(rot, rot, nil, atPathEpoch)
	if burned := burnedIn(dst); len(burned) != 0 {
		t.Errorf("a verdict about epoch %d burned %v while the carrier is on %d", stale, burned, testPathEpoch)
	}

	liveVerdict(t, rc.verdict, testPathEpoch, poolCmd{Cmd: cmdFail, Low: "d1"})
	rc.poll(rot, rot, nil, atPathEpoch)
	if burned := burnedIn(dst); !burned["d1"] {
		t.Error("a verdict on the LIVE path must still burn — the guard drops only the stale one")
	}
}

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

func TestASessionComingUpIsPublishedThoughNoAddressMoved(t *testing.T) {
	var tr pathTracker
	k := pathKey{Src: "10.0.0.1", Sport: 41207, Dst: "10.0.0.2", Dport: 9000}
	tr.observe(k, false)
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
