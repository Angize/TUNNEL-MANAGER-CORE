package packet

import (
	"testing"
	"time"
)

// The very first discarded frame used to log immediately, and because the counter is swapped to zero
// as it logs, that line always read "1 authenticated frames discarded ... in the last 30s". It is the
// line an operator sees first and it understates the problem by whatever the real rate is -- on the
// test pair, by four orders of magnitude: a run throwing away 12,584 frames in thirty seconds reported
// 1. Reading those logs is how the too-narrow window stayed hidden for as long as it did. The first
// drop now only starts the clock, so the first line that prints covers a real window.
func TestTheFirstDropStartsTheWindowInsteadOfReportingOne(t *testing.T) {
	var r replayDropLog
	r.note(4000)
	if got := r.n.Load(); got != 1 {
		t.Fatalf("after the first drop the counter reads %d, want 1 -- it was swapped out to print a line", got)
	}
	if r.last.Load() == 0 {
		t.Fatal("the first drop did not start the clock, so the next drop prints a count of 2")
	}
	if got := r.worst.Load(); got != 4000 {
		t.Fatalf("worst-behind reads %d, want 4000", got)
	}

	for i := 0; i < 500; i++ {
		r.note(uint64(100 + i))
	}
	if got := r.n.Load(); got != 501 {
		t.Fatalf("501 drops inside one window counted as %d: the window is being cut short", got)
	}
	if got := r.worst.Load(); got != 4000 {
		t.Fatalf("worst-behind reads %d after 500 smaller offsets, want the 4000 still standing", got)
	}
}

// The window still has to close, or the count climbs forever and no line ever prints.
func TestTheDropWindowClosesAndResetsItsCount(t *testing.T) {
	var r replayDropLog
	r.note(10)
	r.last.Store(time.Now().Add(-2 * replayDropEvery).UnixNano())
	r.note(20)
	if got := r.n.Load(); got != 0 {
		t.Fatalf("counter reads %d after the window closed, want 0 -- the line printed but the count kept climbing", got)
	}
	if got := r.worst.Load(); got != 0 {
		t.Fatalf("worst-behind reads %d after the window closed, want 0", got)
	}
}
