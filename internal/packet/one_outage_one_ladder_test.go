package packet

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func activeOf(p *PeerPool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[p.cur]
}

func countEv(evs []string, want string) int {
	n := 0
	for _, e := range evs {
		if e == want {
			n++
		}
	}
	return n
}

type ladderRig struct {
	rc       *rotationController
	dst, src *PeerPool
	evs      []string
	now      time.Time
}

func newLadderRig(t *testing.T, dsts, srcs []string) *ladderRig {
	t.Helper()
	dir := t.TempDir()
	rig := &ladderRig{now: time.Now()}
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

func (r *ladderRig) ev(kind, code, detail string) { r.evs = append(r.evs, kind+"/"+code) }

func (r *ladderRig) verdict(cmd string) {
	r.rc.judge(poolCmd{Cmd: cmd, Epoch: testPathEpoch}, r.rotDst, r.rotSrc, r.ev, testPathEpoch, r.now)
}

func (r *ladderRig) untilRest(t *testing.T) {
	t.Helper()
	was := r.rc.restUntil
	for i := 0; i < 64; i++ {
		r.verdict(cmdFail)
		if r.rc.restUntil != was && r.now.Before(r.rc.restUntil) {
			return
		}
	}
	t.Fatal("64 verdicts and the walk never ran out of endpoints")
}

func TestEveryCellOfTheWalkGetsItsOwnDraws(t *testing.T) {
	rig := newLadderRig(t, []string{"d1", "d2", "d3"}, nil)
	rolls, burns := 0, 0
	rig.rc.port.setRoll(func() bool { rolls++; return true }, nil)
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
			rig.rc.port.setRoll(func() bool { draws[cell()]++; return true }, nil)
			rig.rc.session.setDrop(func() bool { return true })

			seen := map[string]bool{}
			for i := 0; i < 8*sh.d*sh.s && rig.rc.restUntil.IsZero(); i++ {
				seen[cell()] = true
				rig.verdict(cmdFail)
			}
			if len(seen) != sh.d*sh.s {
				t.Errorf("the walk stood on %d of the %d cells before it gave up: %v. A destination is "+
					"dead for ONE source, so its burn from the previous row says nothing here — carrying "+
					"it over leaves whole rows of the matrix untried", len(seen), sh.d*sh.s, seen)
			}
			for c := range seen {
				if draws[c] != portTries {
					t.Errorf("cell %s got %d draws, want %d — a cell condemned before its own port "+
						"lottery is run is condemned for a fault that may not be on its axis", c, draws[c], portTries)
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

func TestAFullLapClearsEveryBurnAndRestsTheLadder(t *testing.T) {
	rig := newLadderRig(t, []string{"d1", "d2"}, []string{"s1", "s2"})

	rig.untilRest(t)
	if b := burnedIn(rig.dst); len(b) != 0 {
		t.Errorf("the walk ran out of endpoints and kept %v condemned. A burn is a ranking of one "+
			"endpoint against the others; with every one of them dead it ranks nothing and only "+
			"lengthens the way back", b)
	}
	if b := burnedIn(rig.src); len(b) != 0 {
		t.Errorf("the source axis kept %v condemned after the same lap", b)
	}
	if n := countEv(rig.evs, "down/path-exhausted"); n != 1 {
		t.Fatalf("the lap produced %d path-exhausted lines, want exactly 1: %v", n, rig.evs)
	}

	burnsBefore := countEv(rig.evs, "burn/tun-probe")
	for i := 0; i < 5; i++ {
		rig.verdict(cmdFail)
	}
	if got := countEv(rig.evs, "burn/tun-probe"); got != burnsBefore {
		t.Errorf("the resting ladder burned %d more endpoints. Walking a fully-proven-dead pool again "+
			"every beat is what floods the event ring", got-burnsBefore)
	}
	if n := countEv(rig.evs, "down/path-exhausted"); n != 1 {
		t.Errorf("path-exhausted was written %d times in one outage, want once", n)
	}
}

func TestTheRestEndsOnItsOwnAndOnTheJudgesOK(t *testing.T) {
	t.Run("the rest runs out", func(t *testing.T) {
		rig := newLadderRig(t, []string{"d1", "d2"}, []string{"s1", "s2"})
		rig.untilRest(t)
		was := countEv(rig.evs, "burn/tun-probe")

		rig.now = rig.now.Add(ladderRestMin + time.Second)
		rig.verdict(cmdFail)
		if countEv(rig.evs, "burn/tun-probe") == was {
			t.Error("the rest ran out and the ladder never woke up — the tunnel is parked for good")
		}
	})

	t.Run("traffic crosses", func(t *testing.T) {
		rig := newLadderRig(t, []string{"d1", "d2"}, []string{"s1", "s2"})
		rig.untilRest(t)
		was := countEv(rig.evs, "burn/tun-probe")

		rig.verdict(cmdOK)
		rig.verdict(cmdFail)
		if countEv(rig.evs, "burn/tun-probe") == was {
			t.Error("traffic crossed and the ladder stayed asleep: the rest is for a path nothing " +
				"crosses, and the judge just said something does")
		}
		if n := countEv(rig.evs, "down/path-exhausted"); n != 1 {
			t.Fatalf("setup: %d path-exhausted lines, want 1", n)
		}
		rig.untilRest(t)
		if n := countEv(rig.evs, "down/path-exhausted"); n != 2 {
			t.Errorf("the next outage wrote %d path-exhausted lines in total, want 2 — an ok re-arms "+
				"the line so a second outage is still reported", n)
		}
	})
}

func TestTheRestGrowsWhileNothingCrosses(t *testing.T) {
	rig := newLadderRig(t, []string{"d1", "d2"}, nil)
	lap := func() { rig.untilRest(t) }
	lap()
	first := rig.rc.rest
	if first != ladderRestMin {
		t.Fatalf("the first rest is %v, want %v", first, ladderRestMin)
	}
	for i := 0; i < 6; i++ {
		rig.now = rig.now.Add(rig.rc.rest + time.Second)
		lap()
	}
	if got := rig.rc.rest; got != ladderRestMax {
		t.Errorf("the rest settled at %v, want the %v cap — an outage that never ends must not walk "+
			"the same dead matrix every half minute for ever", got, ladderRestMax)
	}
	rig.verdict(cmdOK)
	if got := rig.rc.rest; got != 0 {
		t.Errorf("the rest kept its %v after traffic crossed: the next outage would start parked", got)
	}
}
