package packet

import (
	"fmt"
	"path/filepath"
	"testing"
)

func activeOf(p *PeerPool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[p.cur]
}

type ladderRig struct {
	rc       *rotationController
	dst, src *PeerPool
}

func newLadderRig(t *testing.T, dsts, srcs []string) *ladderRig {
	t.Helper()
	dir := t.TempDir()
	rig := &ladderRig{}
	if len(dsts) > 0 {
		rig.dst = NewPeerPool(dsts, 0, filepath.Join(dir, "d.json"))
	}
	if len(srcs) > 0 {
		rig.src = NewPeerPool(srcs, 0, filepath.Join(dir, "s.json"))
	}
	rig.rc = newRotationController(rig.dst, rig.src)
	rig.rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	return rig
}

func (r *ladderRig) rotDst(bool) {
	if r.dst != nil {
		r.dst.fail()
	}
}

func (r *ladderRig) rotSrc(bool) {
	if r.src != nil {
		r.src.fail()
	}
}

func TestEveryCellOfTheWalkGetsItsOwnDraws(t *testing.T) {
	rig := newLadderRig(t, []string{"d1", "d2", "d3"}, nil)
	rolls, burns := 0, 0
	rig.rc.port.setRoll(func() bool { rolls++; return true })
	rot := func(bool) { burns++ }

	for i := 1; i <= portTries; i++ {
		rig.rc.fail(rot, nil)
	}
	if rolls != portTries || burns != 0 {
		t.Fatalf("setup: the first cell spent %d draws and condemned %d endpoints, want %d and 0",
			rolls, burns, portTries)
	}
	rig.rc.fail(rot, nil)
	if burns != 1 {
		t.Fatalf("setup: the walk did not take over once the draws were spent (burns=%d)", burns)
	}

	was := rolls
	for i := 1; i <= portTries; i++ {
		rig.rc.fail(rot, nil)
	}
	if got := rolls - was; got != portTries {
		t.Errorf("the second cell got %d draws, want %d. A dead source port is dead for one (source, "+
			"destination, port) triple, so a new endpoint is a new lottery and carrying an empty budget "+
			"into it burns the next endpoint for a fault it never had", got, portTries)
	}
	if burns != 1 {
		t.Errorf("the second cell was condemned after %d burns before spending its own draws", burns)
	}
}

func TestTheWalkVisitsEveryCellOfTheMatrix(t *testing.T) {
	for _, sh := range []struct{ d, s int }{{2, 2}, {3, 2}, {2, 3}} {
		t.Run(fmt.Sprintf("%dx%d", sh.d, sh.s), func(t *testing.T) {
			dsts := make([]string, sh.d)
			for i := range dsts {
				dsts[i] = fmt.Sprintf("d%d", i+1)
			}
			srcs := make([]string, sh.s)
			for i := range srcs {
				srcs[i] = fmt.Sprintf("s%d", i+1)
			}
			rig := newLadderRig(t, dsts, srcs)
			draws := map[string]int{}
			cell := func() string { return activeOf(rig.dst) + "|" + activeOf(rig.src) }
			rig.rc.port.setRoll(func() bool { draws[cell()]++; return true })
			rig.rc.session.setDrop(func() bool { return true })

			seen := map[string]bool{}
			for i := 0; i < 8*sh.d*sh.s; i++ {
				seen[cell()] = true
				rig.rc.fail(rig.rotDst, rig.rotSrc)
			}
			if len(seen) != sh.d*sh.s {
				t.Errorf("the walk stood on %d of the %d cells: %v. A destination is dead for ONE "+
					"source, so its burn from the previous row says nothing here — carrying it over "+
					"leaves whole rows of the matrix untried", len(seen), sh.d*sh.s, seen)
			}
			for c := range seen {
				if draws[c] < portTries {
					t.Errorf("cell %s got %d draws, want at least %d — a cell condemned before its own "+
						"port lottery is run is condemned for a fault that may not be on its axis",
						c, draws[c], portTries)
				}
			}
		})
	}
}

func TestTheBurnedAxisFollowsThePoolShape(t *testing.T) {
	for _, tc := range []struct {
		name             string
		dsts, srcs       []string
		wantDst, wantSrc bool
	}{
		{"one server, many clients", nil, []string{"s1", "s2"}, false, true},
		{"many servers, one client", []string{"d1", "d2"}, []string{"s1"}, true, false},
		{"many of both", []string{"d1", "d2"}, []string{"s1", "s2"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newLadderRig(t, tc.dsts, tc.srcs)
			gotDst, gotSrc := false, false
			for i := 0; i < 6; i++ {
				rig.rc.fail(rig.rotDst, rig.rotSrc)
				gotDst = gotDst || (rig.dst != nil && len(burnedIn(rig.dst)) > 0)
				gotSrc = gotSrc || (rig.src != nil && len(burnedIn(rig.src)) > 0)
			}
			if gotDst != tc.wantDst {
				t.Errorf("destination burned = %v, want %v", gotDst, tc.wantDst)
			}
			if gotSrc != tc.wantSrc {
				t.Errorf("source burned = %v, want %v", gotSrc, tc.wantSrc)
			}
		})
	}
}

func TestAWalkedOutPoolKeepsItsBurnsAndStopsMoving(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(t.TempDir(), "d.json"))
	dst.now = func() int64 { return clk }
	rc := newRotationController(dst, nil)
	rot := func(bool) { dst.fail() }

	for i := 0; i < 3; i++ {
		rc.fail(rot, nil)
	}
	if got := burnedIn(dst); len(got) != 3 {
		t.Fatalf("setup: a full lap left %v condemned, want all three", got)
	}

	parked := activeOf(dst)
	for i := 1; i <= 6; i++ {
		rc.fail(rot, nil)
		if now := activeOf(dst); now != parked {
			t.Fatalf("verdict %d: every endpoint is condemned and none is due for retest, and the pool "+
				"moved %s -> %s anyway. A move tears the session down and builds it again, which on a "+
				"path this bad costs more than it can win — there is nothing better to move to",
				i, parked, now)
		}
	}
	if got := burnedIn(dst); len(got) != 3 {
		t.Errorf("the burns were cleared while the walk ran on: %v. The retest backoff is what decides "+
			"when a condemned endpoint is tried again, and wiping it makes every one of those times "+
			"worth nothing", got)
	}

	clk += suspectBackoff[0]
	rc.fail(rot, nil)
	if activeOf(dst) == parked {
		t.Error("a condemned endpoint came due and the pool did not move onto it — the walk never restarts")
	}
}
