package packet

import "testing"

// burnUntilDue burns addr once and moves the clock to its retest time, leaving it DUE — the state a
// PROACTIVE rotation must now walk past (re-admission belongs to whatever burned it), and that only a
// failover with nothing healthy left may land on.
func burnUntilDue(t *testing.T, p *PeerPool, at int, clk *int64) {
	t.Helper()
	p.mu.Lock()
	p.cur = at
	p.burnLocked(p.addrs[at])
	p.cur = 0
	p.chosen = ""
	p.mu.Unlock()
	r := p.health[p.addrs[at]]
	if r == nil {
		t.Fatalf("burnLocked did not track %s", p.addrs[at])
	}
	*clk = r.nextRetest
}

// TestProactiveRotationPassesOverADueBurnedEndpoint drives the REAL tcp accessors — dialTarget() is what
// the dial uses, sourceIP() what the socket binds to — across a proactive rotation while one endpoint is
// burned with its retest already due. The timed rotation must walk PAST it to a healthy one: a due
// endpoint has answered nothing, and jumping the live tunnel onto it to find out is what the prober
// replaced. Every reader must then agree with what the rotation announced.
func TestProactiveRotationPassesOverADueBurnedEndpoint(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, true, 0, "")
	dst.now = func() int64 { return clk }
	src := NewPeerPool([]string{"192.0.2.1", "192.0.2.2"}, true, 0, "")
	src.now = func() int64 { return clk }
	b := &TCP{pp: dst, sp: src}

	burnUntilDue(t, dst, 1, &clk) // 10.0.0.2 is burned but DUE; 10.0.0.1 and .3 are healthy

	rotated, moved := dst.nextEndpoint(true)
	if !moved || rotated != "10.0.0.3" {
		t.Fatalf("the timed rotation must skip the due-but-burned 10.0.0.2 and take the healthy .3, got (%q,%v)", rotated, moved)
	}
	if got := b.dialTarget(); got != rotated {
		t.Fatalf("the dial went to %s while the rotation announced %s", got, rotated)
	}
	// Every reader must agree, not just the first: the source bind, the status writer and the pin
	// poller all ask again, and any one of them re-selecting re-opens the split.
	if got := b.dialTarget(); got != rotated {
		t.Fatalf("a second read moved the dial target to %s", got)
	}
	if got := dst.current(); got != rotated {
		t.Fatalf("the status writer would publish %s while the tunnel dials %s", got, rotated)
	}

	// With every alternative burned the proactive timer must not move AT ALL — tearing a working
	// connection down to land on an endpoint that has proven nothing is strictly worse than staying.
	burnUntilDue(t, dst, 0, &clk)
	dst.mu.Lock()
	dst.cur, dst.chosen = 2, ""
	dst.mu.Unlock()
	if addr, m := dst.nextEndpoint(true); m {
		t.Fatalf("nothing is healthy — the timed rotation must stay put, it moved to %q", addr)
	}
	if got := b.dialTarget(); got != "10.0.0.3" {
		t.Fatalf("after a rotation that did not move, the dial target is %s, want 10.0.0.3", got)
	}

	// The source pool follows the same rule: its only alternative is burned, so nothing moves.
	burnUntilDue(t, src, 1, &clk)
	if addr, m := src.nextEndpoint(true); m {
		t.Fatalf("the source rotation must stay put with no healthy alternative, it moved to %q", addr)
	}
	if got := b.sourceIP(); got != "192.0.2.1" {
		t.Fatalf("the socket would bind %s, want the unmoved 192.0.2.1", got)
	}
}

// TestFailoverLandsOnADueEndpointAndIsNotSticky covers the one path that may still take a due-burned
// endpoint: a FAILOVER with nothing healthy left, which has to go somewhere. Its choice is honoured by
// every reader, and whichever way the retry then resolves the next read goes back to normal selection.
func TestFailoverLandsOnADueEndpointAndIsNotSticky(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(p *PeerPool)
		want  string
	}{
		// Burning .2 leaves nothing healthy and nothing due, so the least-bad OTHER endpoint wins: .1,
		// whose retest is nearer than the cold .3's.
		{"the retry failed", func(p *PeerPool) { p.fail() }, "10.0.0.1"},
		{"the prober re-admitted it", func(p *PeerPool) { p.retestResult("10.0.0.2", true) }, "10.0.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := int64(1000)
			p := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, true, 0, "")
			p.now = func() int64 { return clk }
			burnUntilDue(t, p, 1, &clk) // .2 burned, retest due
			p.mu.Lock()
			p.health["10.0.0.3"] = &healthRec{state: stateSuspect, nextRetest: clk + 3600} // .3 burned, NOT due
			p.mu.Unlock()
			// cur is .1: the failover burns it, finds nothing healthy, and takes the only DUE endpoint.
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

// TestEveryAdvanceAgreesWithCurrent states the invariant rather than one instance of it: whenever an
// advance reports that it MOVED, the endpoint every consumer then reads must be the one it moved to.
// Both entry points (a proactive rotate and a failover) and every health shape are covered, so a
// future selection rule that reopens the split fails here instead of in the next audit.
func TestEveryAdvanceAgreesWithCurrent(t *testing.T) {
	// burn describes which pool members start burned, and whether their retest is already due.
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
				p := NewPeerPool([]string{"a", "b", "c", "d"}, true, 0, "")
				p.now = func() int64 { return clk }
				p.mu.Lock()
				for _, i := range tc.burnedDue {
					p.health[p.addrs[i]] = &healthRec{state: stateSuspect, nextRetest: clk - 1}
				}
				for _, i := range tc.burnedCold {
					p.health[p.addrs[i]] = &healthRec{state: stateSuspect, nextRetest: clk + 3600}
				}
				p.cur = 0
				p.mu.Unlock()
				addr, moved := p.nextEndpoint(proactive)
				if !moved {
					return // nothing to agree about
				}
				if got := p.current(); got != addr {
					t.Fatalf("proactive=%v: the advance moved to %s but current() reads %s", proactive, addr, got)
				}
			})
		}
	}
}
