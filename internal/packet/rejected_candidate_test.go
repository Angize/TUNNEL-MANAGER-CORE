package packet

import (
	"path/filepath"
	"testing"
)

// rejectCandidate undoes a SOURCE rotation whose target the host refused to bind: the socket never left
// the previous IP, so the pool must point back at it. That part is right. What it also did was wipe the
// previous source's health record outright -- and "some OTHER IP would not bind" is not evidence about
// this one. It is the same local-evidence acquittal the whole pool was rebuilt to remove, reached
// through the one door nobody looked at.

// TestARejectedCandidateDoesNotLaunderTheLiveSource drives the proactive case, where the point is
// sharpest: no burn was recorded this round at all, so there is nothing to undo, and the clear can only
// erase a ladder some earlier verdict earned.
func TestARejectedCandidateDoesNotLaunderTheLiveSource(t *testing.T) {
	p := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(t.TempDir(), "s.json"))
	clk := int64(1000)
	p.now = func() int64 { return clk }

	// s1 has been failing for a while — several rounds down the ladder, not a fresh mark.
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
	p.rejectCandidate("s1") // ...and the host refuses to bind s2

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

	// ...and the tunnel is NOT stranded: the pool still hands back the source the socket is really on,
	// burned or not, because rejectCandidate commits to it.
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

// TestARejectedCandidateStillUndoesTheRoundsOwnBurn is the failover case, and the reason the clear was
// written. There the burn on s1 IS from this round -- but it was earned by a real verdict about the
// tunnel, and the move failing does not unmake the measurement. What must not happen is the pool losing
// track of where the socket actually is.
func TestARejectedCandidateStillUndoesTheRoundsOwnBurn(t *testing.T) {
	p := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(t.TempDir(), "s.json"))
	if _, moved := p.fail(); !moved {
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
