package packet

import (
	"testing"
)

func TestARejectedCandidateDoesNotLaunderTheLiveSource(t *testing.T) {
	p := NewPeerPool([]string{"s1", "s2"}, 0)
	clk := int64(1000)
	p.now = func() int64 { return clk }

	p.mu.Lock()
	p.health.burn("s1")
	r := p.health.rec("s1")
	retestBackoff(r, clk)
	retestBackoff(r, clk)
	before := *r
	p.mu.Unlock()

	if _, moved := p.rotateOnce(); !moved {
		t.Fatal("setup: the proactive rotation did not move onto s2")
	}
	p.rejectCandidate("s1")

	p.mu.Lock()
	after := p.health.rec("s1")
	s2Burned := !p.health.healthy("s2")
	p.mu.Unlock()

	if after == nil {
		t.Fatal("s2 could not be bound, and that cleared s1's burn — nothing measured s1 here, and on " +
			"the proactive path nothing had even burned it this round. The one source the socket is " +
			"stuck on now reads healthy, and the ladder that was deciding when to try it again is gone")
	}
	if after.fails != before.fails || after.state != before.state {
		t.Fatalf("s1's ladder was reset: %+v, want %+v", *after, before)
	}
	if !s2Burned {
		t.Fatal("the candidate the host cannot bind was not pulled from rotation — it is a local fact " +
			"no policy changes, and leaving it healthy makes the rotation return to it")
	}

	if got := p.current(); got != "s1" {
		t.Fatalf("current() gave %q — the socket is on s1 and the pool must keep naming it, or the "+
			"status file names a source the datagram path never adopted", got)
	}
	for i := 0; i < 5; i++ {
		if got := p.current(); got != "s1" {
			t.Fatalf("ask %d gave %q — the commitment must hold, not decay after one read", i, got)
		}
	}
}

func TestARejectedCandidateStillUndoesTheRoundsOwnBurn(t *testing.T) {
	p := NewPeerPool([]string{"s1", "s2"}, 0)
	if _, moved := p.fail("tun-probe"); !moved {
		t.Fatal("setup: the failover did not move")
	}
	p.rejectCandidate("s1")

	if got := p.current(); got != "s1" {
		t.Fatalf("after the candidate was refused, current() gave %q — the socket never left s1", got)
	}
	p.mu.Lock()
	s2Burned := !p.health.healthy("s2")
	p.mu.Unlock()
	if !s2Burned {
		t.Fatal("the unbindable candidate must be pulled from rotation")
	}
}
