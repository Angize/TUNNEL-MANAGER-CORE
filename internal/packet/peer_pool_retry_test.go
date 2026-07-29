package packet

import "testing"

// burnUntilDue burns addr once and moves the clock to its retest time, leaving it DUE — the state in
// which the pool is supposed to re-admit it for a live retry (the direct transports have no
// out-of-band prober, so the data plane itself is the probe).
func burnUntilDue(t *testing.T, p *PeerPool, at int, clk *int64) {
	t.Helper()
	p.mu.Lock()
	p.cur = at
	p.burnLocked(p.addrs[at])
	p.cur = 0
	p.mu.Unlock()
	r := p.health[p.addrs[at]]
	if r == nil {
		t.Fatalf("burnLocked did not track %s", p.addrs[at])
	}
	*clk = r.nextRetest
}

// TestTCPDialsTheEndpointTheRotationChose drives the REAL tcp accessors — dialTarget() is what the
// dial uses and sourceIP() is what the socket binds to — across a proactive rotation onto a burned
// endpoint whose retest is due.
//
// Before the fix these two disagreed with the rotation. advanceEligibleLocked accepts a DUE burned
// endpoint (that re-admission is the retest), but current()'s first pass refuses a burned endpoint
// while any healthy one exists and silently reset cur, so dialTarget() handed back the endpoint the
// tunnel was already on. The rotation timer therefore tore down a healthy connection and rebuilt it
// to the SAME address every interval, forever; the peer-rotate event and the status file both named
// an endpoint the tunnel was not on; and the due endpoint was never dialled, so it never healed and
// "probe now" (which only pulls the backoff forward) had nothing to trigger. udp/raw/flux consume the
// address nextEndpoint returns and were never affected.
func TestTCPDialsTheEndpointTheRotationChose(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, true, 0, "")
	dst.now = func() int64 { return clk }
	src := NewPeerPool([]string{"192.0.2.1", "192.0.2.2"}, true, 0, "")
	src.now = func() int64 { return clk }
	b := &TCP{pp: dst, sp: src}

	burnUntilDue(t, dst, 1, &clk) // 10.0.0.2 is burned but DUE; 10.0.0.1 and .3 are healthy
	burnUntilDue(t, src, 1, &clk) // 192.0.2.2 likewise

	rotated, moved := dst.nextEndpoint(true)
	if !moved || rotated != "10.0.0.2" {
		t.Fatalf("the rotation should have moved onto the due endpoint, got (%q,%v)", rotated, moved)
	}
	if got := b.dialTarget(); got != rotated {
		t.Fatalf("the dial went to %s while the rotation announced %s — a healthy connection is torn down and rebuilt to the same endpoint every interval, and %s is never retried", got, rotated, rotated)
	}
	// Every reader must agree, not just the first: the source bind, the status writer and the pin
	// poller all ask again, and any one of them resetting cur re-opens the same hole.
	if got := b.dialTarget(); got != rotated {
		t.Fatalf("a second read moved the dial target to %s", got)
	}
	if got := dst.current(); got != rotated {
		t.Fatalf("the status writer would publish %s while the tunnel dials %s", got, rotated)
	}

	rotatedSrc, movedSrc := src.nextEndpoint(true)
	if !movedSrc || rotatedSrc != "192.0.2.2" {
		t.Fatalf("the source rotation should have moved onto the due source, got (%q,%v)", rotatedSrc, movedSrc)
	}
	if got := b.sourceIP(); got != rotatedSrc {
		t.Fatalf("the socket would bind %s while the source rotation announced %s", got, rotatedSrc)
	}
}

// TestRetriedEndpointIsNotSticky is the other half: honouring the rotation's choice must not pin the
// tunnel to a bad endpoint. Whichever way the retry resolves — the dial fails, or it succeeds — the
// next read must go back to normal selection.
func TestRetriedEndpointIsNotSticky(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(p *PeerPool)
		want  string
	}{
		{"the retry failed", func(p *PeerPool) { p.fail() }, "10.0.0.3"},
		{"the retry connected", func(p *PeerPool) { p.succeeded() }, "10.0.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := int64(1000)
			p := NewPeerPool([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, true, 0, "")
			p.now = func() int64 { return clk }
			burnUntilDue(t, p, 1, &clk)
			if a, moved := p.nextEndpoint(true); !moved || a != "10.0.0.2" {
				t.Fatalf("setup: rotation did not reach the due endpoint, got (%q,%v)", a, moved)
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
