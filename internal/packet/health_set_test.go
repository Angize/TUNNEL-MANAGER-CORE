package packet

import (
	"testing"
	"time"
)

func TestHealthSetReadsTheOwnersClock(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, 0)
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
		clk = r.nextRetest
		h.burn("a")
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

// The ranking every pool falls back to when nothing is healthy and nothing is due yet. It used to have
// a second implementation on healthSet, reachable only from the edge pool; with one pool for every
// carrier there is one, and this is it.
func burnAt(p *PeerPool, key, state string, at int64) {
	p.mu.Lock()
	p.health.recs[key] = &healthRec{state: state, nextRetest: at}
	p.mu.Unlock()
}

func bestOf(p *PeerPool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[p.bestIdxLocked(-1)]
}

func TestTheFallbackRanksByTierThenBySoonestRetest(t *testing.T) {
	clk := int64(5000)
	load := func(addrs ...string) *PeerPool {
		p := NewPeerPool(addrs, 0)
		p.now = func() int64 { return clk }
		burnAt(p, "a", stateDead, clk+5)
		burnAt(p, "b", stateSuspect, clk+900)
		burnAt(p, "c", stateSuspect, clk+10)
		return p
	}

	if got := bestOf(load("a", "b", "c")); got != "c" {
		t.Fatalf("best = %s, want c (suspect beats dead; soonest retest beats a later one)", got)
	}
	if got := bestOf(load("a", "b", "c", "d")); got != "d" {
		t.Fatalf("best = %s, want d — an untracked entry is healthy and outranks every burned one", got)
	}
}

func TestRetestNowEndsOneWaitAndOnlyThatOne(t *testing.T) {
	clk := time.Now().Unix()
	h := newHealthSet(&[]func() int64{func() int64 { return clk }}[0])
	h.burn("a")
	h.burn("b")
	h.recs["b"].state = stateDead
	h.recs["b"].nextRetest = clk + deadRetest

	if h.retestNow("nobody") {
		t.Fatal("an entry that carries no record reported a wait it does not have")
	}
	if !h.retestNow("a") {
		t.Fatal("retestNow did not report that it ended a's wait")
	}
	if h.due("b") {
		t.Fatal("ending a's wait ended b's too — the operator asked for ONE entry, and zeroing the " +
			"others makes their backoff a lie")
	}
	h.retestNow("b")
	for _, k := range []string{"a", "b"} {
		if !h.due(k) {
			t.Fatalf("%s is still waiting after retestNow (nextRetest-now=%d)", k, h.rec(k).nextRetest-clk)
		}
		if h.healthy(k) {
			t.Fatalf("%s was CLEARED, not pulled forward — retest hands an entry to the judge, it is not a verdict", k)
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

// The SNI hosts are a PeerPool of their own now, and they keep the rule the edge pool had: verdicts that
// arrive while an entry is still waiting out its backoff must not walk its ladder.
func TestMarkSuspectDoesNotStepAWaitingEntry(t *testing.T) {
	b := edgeTCP([]string{"e1", "e2"}, snis("s1", "s2"), 0)
	clk := int64(5000)
	b.sp.now = func() int64 { return clk }

	b.sp.markSuspect("s1", "tun-probe")
	b.sp.mu.Lock()
	first := b.sp.health.rec("s1").nextRetest
	b.sp.mu.Unlock()
	b.sp.markSuspect("s1", "tun-probe")
	b.sp.markSuspect("s1", "tun-probe")

	b.sp.mu.Lock()
	r := b.sp.health.rec("s1")
	next, fails := r.nextRetest, r.fails
	b.sp.mu.Unlock()
	if next != first || fails != 0 {
		t.Fatalf("repeated verdicts on one SNI walked its ladder: fails=%d nextRetest%+d", fails, next-first)
	}
}
