package packet

import (
	"path/filepath"
	"testing"
)

// TestBurnAdvanceLapIsSizedOnce closes the class behind a source being convicted a step early.
//
// The two pools are an odometer: every destination is tried against the current source, and only once
// they are all spent is that source the one thing that did not vary. Sizing that lap by re-reading
// eligibleCount() on each ask is the trap — the ask before it BURNED a destination, and a burned entry
// is not eligible, so the number shrinks by one exactly as the counter grows by one. Three destinations
// then declare a lap after two, and the source that was never disproved is walked off.
//
// rotationController.fail (the udp/flux path) snapshots it at the start of the round; this is the same
// invariant for the tcp path, which reaches its odometer through burnAdvance instead.
func TestBurnAdvanceLapIsSizedOnce(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "dst.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "src.json")),
	}
	start := b.sp.current()
	for i := 1; i <= 3; i++ {
		b.burnAdvance(true)
		moved := b.sp.current() != start
		if i < 3 && moved {
			t.Fatalf("the source moved after %d of 3 destinations (%s -> %s): the lap was re-sized "+
				"against a list the burns had already shrunk", i, start, b.sp.current())
		}
		if i == 3 && !moved {
			t.Fatalf("every destination was tried and the source still did not move (still %s)", start)
		}
	}
}

// TestBurnAdvanceLapResetsOnAHealthySession: the round is a round, not a lifetime. A session that comes
// up healthy clears the counter, so the next outage starts its own lap instead of finishing the last one
// and walking the source on its first ask.
func TestBurnAdvanceLapResetsOnAHealthySession(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "dst.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "src.json")),
	}
	b.burnAdvance(true)
	b.burnAdvance(true)
	b.destRot.Store(0) // what dialLoop's succeedBoth does when a carrier proves healthy
	b.pp.probeAllNow()
	b.pp.clearBurn("d1")
	b.pp.clearBurn("d2")

	start := b.sp.current()
	b.burnAdvance(true)
	if b.sp.current() != start {
		t.Fatalf("the first ask of a FRESH round moved the source (%s -> %s): the lap size was carried "+
			"over from the previous outage", start, b.sp.current())
	}
}
