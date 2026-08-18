package packet

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHealthSetReadsTheOwnersClock(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
	clk := int64(1000)
	p.now = func() int64 { return clk }

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

func TestABurnStepsOnlyTheEntryItMeasured(t *testing.T) {
	clk := int64(5000)
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])

	if !h.burn("a") {
		t.Fatal("the first burn must report the transition")
	}
	first := h.rec("a").nextRetest
	for i := 0; i < 5; i++ {
		if h.burn("a") {
			t.Fatal("a repeat burn is not a transition")
		}
	}
	r := h.rec("a")
	if r.nextRetest != first || r.fails != 0 || r.state != stateSuspect {
		t.Fatalf("five verdicts arriving DURING the wait moved the entry: fails=%d state=%v nextRetest%+d "+
			"— the scheduler owns its cadence while it waits", r.fails, r.state, r.nextRetest-first)
	}

	clk = first
	h.burn("a")
	if h.rec("a").nextRetest == first || h.rec("a").fails == 0 {
		t.Fatal("a verdict on a DUE entry did not walk the ladder — it stays due, and every rotation tick " +
			"then walks straight back onto a dead entry, forever")
	}
}

func TestMarkSuspectDoesNotStepAWaitingEntry(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), filepath.Join(t.TempDir(), "st.json"))
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
