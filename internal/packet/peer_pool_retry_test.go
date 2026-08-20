package packet

import (
	"testing"
	"time"
)

func burnUntilDue(t *testing.T, p *PeerPool, at int, clk *int64) {
	t.Helper()
	p.mu.Lock()
	p.cur = at
	p.burnLocked(p.addrs[at])
	p.cur = 0
	p.chosen = ""
	p.mu.Unlock()
	r := p.health.recs[p.addrs[at]]
	if r == nil {
		t.Fatalf("burnLocked did not track %s", p.addrs[at])
	}
	*clk = r.nextRetest
}

func TestProactiveRotationRetriesADueBurnButNotAPendingOne(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	dst.now = func() int64 { return clk }
	src := NewPeerPool([]string{"192.0.2.1", "192.0.2.2"}, 0)
	src.now = func() int64 { return clk }
	b := &TCP{isClient: true}
	b.SetPeerPool(dst)
	b.SetSourcePool(src)

	burnUntilDue(t, dst, 1, &clk)

	rotated, moved := dst.nextEndpoint(true)
	if !moved || rotated != "10.0.0.2" {
		t.Fatalf("a due burn is the next thing to retry, got (%q,%v)", rotated, moved)
	}
	if got := b.dialTarget(); got != rotated {
		t.Fatalf("the dial went to %s while the rotation announced %s", got, rotated)
	}

	if got := b.dialTarget(); got != rotated {
		t.Fatalf("a second read moved the dial target to %s", got)
	}
	if got := dst.current(); got != rotated {
		t.Fatalf("the status writer would publish %s while the tunnel dials %s", got, rotated)
	}

	p2 := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
	p2.now = func() int64 { return clk }
	p2.mu.Lock()
	p2.health.recs["10.0.0.2"] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
	p2.cur, p2.chosen = 0, ""
	p2.mu.Unlock()
	if a, m := p2.nextEndpoint(true); !m || a != "10.0.0.3" {
		t.Fatalf("a pending burn must be passed over for the healthy .3, got (%q,%v)", a, m)
	}

	p2.mu.Lock()
	p2.health.recs["10.0.0.1"] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
	p2.mu.Unlock()
	if a, m := p2.nextEndpoint(true); m {
		t.Fatalf("nothing is eligible — the timer must stay put, it moved to %q", a)
	}
	if got := b.sourceIP(); got != "192.0.2.1" {
		t.Fatalf("the socket would bind %s, want the unmoved 192.0.2.1", got)
	}
}

func TestFailoverLandsOnADueEndpointAndIsNotSticky(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(p *PeerPool)
		want  string
	}{

		{"the retry failed", func(p *PeerPool) { p.fail("tun-probe") }, "10.0.0.1"},
		{"the node reported it carrying", func(p *PeerPool) { p.clearBurn("10.0.0.2") }, "10.0.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := int64(1000)
			p := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 0)
			p.now = func() int64 { return clk }
			burnUntilDue(t, p, 1, &clk)
			p.mu.Lock()
			p.health.recs["10.0.0.3"] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
			p.mu.Unlock()

			if a, moved := p.nextEndpoint(false); !moved || a != "10.0.0.2" {
				t.Fatalf("setup: the failover did not reach the due endpoint, got (%q,%v)", a, moved)
			}
			if got := p.current(); got != "10.0.0.2" {
				t.Fatalf("every reader must honour the failover's choice, current() reads %s", got)
			}
			tc.after(p)
			if got := p.current(); got != tc.want {
				t.Fatalf("after %s the pool should be on %s, got %s", tc.name, tc.want, got)
			}
		})
	}
}

func TestEveryAdvanceAgreesWithCurrent(t *testing.T) {

	for _, tc := range []struct {
		name       string
		burnedDue  []int
		burnedCold []int
	}{
		{name: "all healthy"},
		{name: "one due", burnedDue: []int{1}},
		{name: "two due", burnedDue: []int{1, 2}},
		{name: "one due, one not yet", burnedDue: []int{1}, burnedCold: []int{2}},
		{name: "all but one burned and due", burnedDue: []int{1, 2, 3}},
		{name: "everything burned, none due", burnedCold: []int{0, 1, 2, 3}},
		{name: "everything burned, all due", burnedDue: []int{0, 1, 2, 3}},
	} {
		for _, proactive := range []bool{true, false} {
			t.Run(tc.name, func(t *testing.T) {
				clk := int64(100000)
				p := NewPeerPool([]string{"a", "b", "c", "d"}, 0)
				p.now = func() int64 { return clk }
				p.mu.Lock()
				for _, i := range tc.burnedDue {
					p.health.recs[p.addrs[i]] = &healthRec{state: stateSuspect, nextRetest: clk - 1}
				}
				for _, i := range tc.burnedCold {
					p.health.recs[p.addrs[i]] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
				}
				p.cur = 0
				p.mu.Unlock()
				addr, moved := p.nextEndpoint(proactive)
				if !moved {
					return
				}
				if got := p.current(); got != addr {
					t.Fatalf("proactive=%v: the advance moved to %s but current() reads %s", proactive, addr, got)
				}
			})
		}
	}
}

func TestTheRotationWalksEveryCombination(t *testing.T) {
	dst := NewPeerPool([]string{"d1", "d2"}, time.Minute)
	src := NewPeerPool([]string{"s1", "s2"}, time.Minute)
	rc := newRotationController(dst, src)
	rotDst := func(bool) { dst.nextEndpoint(true) }
	rotSrc := func(bool) { src.nextEndpoint(true) }

	at := time.Now()
	var got []string
	for i := 0; i < 4; i++ {
		at = at.Add(2 * time.Minute)
		rc.proactive(rotDst, rotSrc, at)
		got = append(got, src.current()+" -> "+dst.current())
	}
	want := []string{"s1 -> d1", "s2 -> d2", "s2 -> d1", "s1 -> d2"}

	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	if len(seen) != 4 {
		t.Fatalf("a 2x2 pool must produce four distinct combinations in four beats, got %v (want the set of %v)", got, want)
	}
	for g, n := range seen {
		if n != 1 {
			t.Fatalf("%s came up %d times in one cycle: %v", g, n, got)
		}
	}

	dst.mu.Lock()
	dst.health.recs["d2"] = &healthRec{state: stateSuspect, nextRetest: dst.now() + 3600}
	dst.mu.Unlock()
	before := src.current()
	at = at.Add(2 * time.Minute)
	rc.proactive(rotDst, rotSrc, at)
	if src.current() == before {
		t.Fatalf("the destination cannot move, so the source must — it stayed on %s", before)
	}
}

func TestASourceIsOnlyBlamedAfterARealLap(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d1", "d2"}, 0)
	dst.now = func() int64 { return clk }
	src := NewPeerPool([]string{"s1", "s2"}, 0)
	src.now = func() int64 { return clk }
	dst.mu.Lock()
	dst.health.recs["d2"] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
	dst.mu.Unlock()

	rc := newRotationController(dst, src)
	srcMoves := 0
	rotDst := func(bool) { dst.fail("tun-probe") }
	rotSrc := func(bool) { srcMoves++ }
	for i := 0; i < 3; i++ {
		rc.fail(rotDst, rotSrc)
	}
	if srcMoves != 3 {
		t.Fatalf("with ONE eligible destination every ask is a full lap, so the source moves each time; got %d", srcMoves)
	}

	dst2 := NewPeerPool([]string{"d1", "d2"}, 0)
	src2 := NewPeerPool([]string{"s1", "s2"}, 0)
	rc2 := newRotationController(dst2, src2)
	srcMoves = 0
	rc2.fail(func(bool) {}, rotSrc)
	if srcMoves != 0 {
		t.Fatalf("one ask of two eligible destinations is not a lap, got %d source moves", srcMoves)
	}
	rc2.fail(func(bool) {}, rotSrc)
	if srcMoves != 1 {
		t.Fatalf("the second ask completes the lap, got %d source moves", srcMoves)
	}
}
