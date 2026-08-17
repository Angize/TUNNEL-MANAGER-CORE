package packet

import "sync"

// odometer is the two-digit counter that turns "this combination is dead" into "which axis was the one
// that did not vary". The LOW digit advances every round; the HIGH one moves only once the low has
// covered everything it could have tried, and that is the whole attribution — the axis you were forced
// to leave is the one that was never the problem.
//
// One of these, not three. The datagram carriers walk destination-then-source, the direct-tcp carrier
// walks the same pair, and the edge pool walks SNI-then-edge: the same rule, written out three times
// with the same field names. The copies had already begun to disagree about when the failover count
// restarts, which is what a fourth copy would have inherited.
//
// The lock covers each whole decision, not each field. Two of the counters it replaces were plain
// atomics reached from both the dial loop and the verdict poller, so a round's read-decide-write could
// interleave with a reset and size a lap against a round that had just been cleared.
type odometer struct {
	mu   sync.Mutex
	rot  int // rounds spent on the low digit since the high one last moved
	want int // how many the low digit could try this round, sized once at its start
	tick int // proactive beats since the high digit last moved
}

// failed records one proven-dead round on the low axis and reports whether the HIGH axis should now
// move: every entry the low one could have tried has been.
//
// eligible is read ONCE per round, at its start, and only then — re-reading it after each burn is the
// trap, because every burn shrinks the number the next round compares against and three entries
// declare a lap after two. Call this BEFORE the burn, so the count it snapshots is the one that was
// available to try.
//
// A zero count needs no floor: the first round takes rot to 1, and 1 >= 0 completes the lap exactly as
// 1 >= 1 would. All three copies this replaces carried that floor with a paragraph defending it.
func (o *odometer) failed(eligible func() int) (advanceHigh bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rot == 0 {
		o.want = eligible()
	}
	if o.rot++; o.rot >= o.want {
		o.rot = 0
		return true
	}
	return false
}

// beat records one proactive rotation of the low axis and reports whether the HIGH one should follow.
// A low axis that could not move has, trivially, been all the way round.
//
// It clears the failover round too. That count means "every low entry tried against THIS high one", so
// it cannot survive the high one changing — one of the three copies said so and reset it here, the
// other left it to the carrier's teardown path, which does not run when a proactive rotation is undone
// by a failed warm build.
//
// want is cleared with it although nothing reads a stale one — failed() re-sizes whenever rot is zero.
// It is here so a reset leaves the zero value, rather than a state a reader has to prove harmless.
func (o *odometer) beat(moved bool, eligible func() int) (advanceHigh bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tick++
	if !moved || o.tick >= eligible() {
		o.tick, o.rot, o.want = 0, 0, 0
		return true
	}
	return false
}

// restart clears the failover round because a live carrier invalidated it. It leaves the proactive
// beat alone: that is a schedule rather than a round, and nothing ever reset it here.
func (o *odometer) restart() {
	o.mu.Lock()
	o.rot, o.want = 0, 0
	o.mu.Unlock()
}
