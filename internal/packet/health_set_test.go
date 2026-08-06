package packet

import (
	"path/filepath"
	"testing"
	"time"
)

// TestHealthSetReadsTheOwnersClock is the trap this type could most easily have introduced, and it is
// invisible from every other test: both pools let a test replace their `now` field AFTER construction,
// so a healthSet that captured a copy of the clock would age its entries against the real wall clock
// while the pool aged against the fake one. Nothing would fail loudly — the ladder would simply stop
// being exercised, and every backoff test would pass for the wrong reason.
func TestHealthSetReadsTheOwnersClock(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, filepath.Join(t.TempDir(), "p.json"))
	clk := int64(1000)
	p.now = func() int64 { return clk } // exactly what the pool tests do

	p.mu.Lock()
	p.health.burn("a")
	got := p.health.rec("a").nextRetest
	p.mu.Unlock()

	if want := clk + suspectBackoff[0]; got != want {
		t.Fatalf("nextRetest = %d, want %d — the set is on its own clock, not the pool's", got, want)
	}

	p.mu.Lock()
	due := p.health.due("a")
	p.mu.Unlock()
	if due {
		t.Fatal("the entry is due immediately: the set read a clock the test does not control")
	}

	clk += suspectBackoff[0]
	p.mu.Lock()
	due = p.health.due("a")
	p.mu.Unlock()
	if !due {
		t.Fatal("the backoff elapsed on the pool's clock and the set did not notice")
	}
}

// TestHealthSetLadder walks the FSM the way a failing entry really does: suspect at the first step, one
// step per failure, dead once the schedule runs out, and the slow interval from then on. Each wait must
// be longer than the one before — the backwards-backoff bug was a record entering at one step while its
// counter said another.
func TestHealthSetLadder(t *testing.T) {
	clk := int64(5000)
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])

	if fresh := h.burn("a"); !fresh {
		t.Fatal("the first burn must report itself as the transition")
	}
	if fresh := h.burn("a"); fresh {
		t.Fatal("a repeat burn is not a transition — logging it every time is noise")
	}

	prev := int64(-1)
	for i := 0; i < len(suspectBackoff)+2; i++ {
		r := h.rec("a")
		if r == nil {
			t.Fatal("the entry vanished mid-ladder")
		}
		wait := r.nextRetest - clk
		if wait <= prev && r.state != stateDead {
			t.Fatalf("step %d waits %ds, no longer than the previous %ds — the ladder ran backwards", i, wait, prev)
		}
		prev = wait
		h.retestFailed(r)
	}
	if r := h.rec("a"); r.state != stateDead || r.nextRetest != clk+deadRetest {
		t.Fatalf("after the schedule ran out: state=%v nextRetest-now=%d, want dead on %d",
			r.state, r.nextRetest-clk, deadRetest)
	}
}

// TestHealthSetEligibleVsHealthy pins the distinction the lap counter depends on: a burned entry whose
// backoff has elapsed is NOT healthy but IS eligible. Collapsing the two is what makes a walk either
// skip an endpoint that could have been tried, or declare a lap that never happened.
func TestHealthSetEligibleVsHealthy(t *testing.T) {
	clk := int64(5000)
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])
	keys := []string{"a", "b", "c"}

	h.burn("a")
	if n := h.countEligible(keys); n != 2 {
		t.Fatalf("one entry just burned, %d eligible, want 2", n)
	}
	clk += suspectBackoff[0]
	if h.healthy("a") {
		t.Fatal("a burned entry whose backoff elapsed is DUE, never healthy")
	}
	if !h.eligible("a") || !h.due("a") {
		t.Fatal("its backoff elapsed, so it is eligible and due")
	}
	if n := h.countEligible(keys); n != 3 {
		t.Fatalf("the burned entry came due, %d eligible, want 3", n)
	}
	if !h.clear("a") {
		t.Fatal("clear must report that it removed a record")
	}
	if h.clear("a") {
		t.Fatal("clearing an untracked entry removed nothing and must say so")
	}
}

// TestHealthSetBestRanksByTier: the last-resort pick is healthy < suspect < dead, with the soonest
// retest breaking a tie. It is what stops a pool with everything burned from dead-ending.
func TestHealthSetBestRanksByTier(t *testing.T) {
	clk := int64(5000)
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])

	h.recs["a"] = &healthRec{state: stateDead, nextRetest: clk + 5}
	h.recs["b"] = &healthRec{state: stateSuspect, nextRetest: clk + 900}
	h.recs["c"] = &healthRec{state: stateSuspect, nextRetest: clk + 10}
	if got := h.best([]string{"a", "b", "c"}); got != "c" {
		t.Fatalf("best = %s, want c (suspect beats dead; soonest retest beats a later one)", got)
	}
	if got := h.best([]string{"a", "b", "c", "d"}); got != "d" {
		t.Fatalf("best = %s, want d — an untracked entry is healthy and outranks every burned one", got)
	}
	if got := h.best(nil); got != "" {
		t.Fatalf("best of nothing = %q, want empty", got)
	}
}

// TestHealthSetProbeAllNow: the operator's "probe now" and the node's end-of-matrix restore both pull
// every waiting entry forward at once, so the rotation may reach them on its very next pick.
func TestHealthSetProbeAllNow(t *testing.T) {
	clk := time.Now().Unix()
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])
	h.burn("a")
	h.burn("b")
	h.recs["b"].state = stateDead
	h.recs["b"].nextRetest = clk + deadRetest

	h.probeAllNow()
	for _, k := range []string{"a", "b"} {
		if !h.due(k) {
			t.Fatalf("%s is still waiting after probeAllNow (nextRetest-now=%d)", k, h.rec(k).nextRetest-clk)
		}
		if h.healthy(k) {
			t.Fatalf("%s was CLEARED, not pulled forward — probe-now hands entries to the judge, it is not a verdict", k)
		}
	}
}

// TestSidelineDoesNotWalkTheLadder is the difference between the two pools' burns, and it is worth its
// own test because collapsing them is silent: everything still compiles, every other test still passes,
// and the only symptom is a CDN edge racing to dead several verdicts sooner than its schedule says.
//
// markSuspect (edge pool) SIDELINES: from the first burn on, the retest scheduler owns that entry's
// cadence, and a second live verdict arriving while it waits must not push it further down. burnLocked
// (direct pool) BURNS: its failures come one per failover round, so stepping is the ladder working.
func TestSidelineDoesNotWalkTheLadder(t *testing.T) {
	clk := int64(5000)
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])

	if !h.sideline("a") {
		t.Fatal("the first sideline must report the transition")
	}
	first := h.rec("a").nextRetest
	for i := 0; i < 5; i++ {
		if h.sideline("a") {
			t.Fatal("a repeat sideline is not a transition")
		}
	}
	r := h.rec("a")
	if r.nextRetest != first || r.fails != 0 || r.state != stateSuspect {
		t.Fatalf("five more verdicts moved a sidelined entry: fails=%d state=%v nextRetest%+d — the "+
			"scheduler owns its cadence from the first burn on", r.fails, r.state, r.nextRetest-first)
	}

	// ...while burn() is the other half of the pair and MUST step.
	h.burn("b")
	stepped := h.rec("b").nextRetest
	h.burn("b")
	if h.rec("b").nextRetest == stepped || h.rec("b").fails == 0 {
		t.Fatal("burn must walk the ladder on a repeat — that is what makes the direct pool's rounds count")
	}
}

// TestMarkSuspectSidelines drives the real caller, not the helper: the edge pool's markSuspect must not
// step an entry that a previous verdict already burned.
func TestMarkSuspectSidelines(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), true, filepath.Join(t.TempDir(), "st.json"))
	clk := int64(5000)
	p.now = func() int64 { return clk }

	p.markSuspect("sni", "s1", "tun-probe")
	first := p.sniHealth.rec("s1").nextRetest
	p.markSuspect("sni", "s1", "tun-probe")
	p.markSuspect("sni", "s1", "tun-probe")

	r := p.sniHealth.rec("s1")
	if r.nextRetest != first || r.fails != 0 {
		t.Fatalf("repeated verdicts on one SNI walked its ladder: fails=%d nextRetest%+d", r.fails, r.nextRetest-first)
	}
}
