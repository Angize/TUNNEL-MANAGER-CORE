package packet

import (
	"path/filepath"
	"testing"
)

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

func TestBurnAdvanceLapResetsOnAHealthySession(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "dst.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "src.json")),
	}
	b.burnAdvance(true)
	b.burnAdvance(true)
	b.odPeer.restart()
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
