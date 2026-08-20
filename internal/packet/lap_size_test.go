package packet

import (
	"testing"
)

func TestBurnAdvanceLapIsSizedOnce(t *testing.T) {
	b, _, sp := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})
	start := sp.current()
	for i := 1; i <= 3; i++ {
		tcpWalk(b)
		moved := sp.current() != start
		if i < 3 && moved {
			t.Fatalf("the source moved after %d of 3 destinations (%s -> %s): the lap was re-sized "+
				"against a list the burns had already shrunk", i, start, sp.current())
		}
		if i == 3 && !moved {
			t.Fatalf("every destination was tried and the source still did not move (still %s)", start)
		}
	}
}

func TestBurnAdvanceLapResetsOnAHealthySession(t *testing.T) {
	b, pp, sp := peerCarrier(t, []string{"d1", "d2", "d3"}, []string{"s1", "s2"})
	tcpWalk(b)
	tcpWalk(b)
	b.rc.od.restart()
	pp.clearBurn("d1")
	pp.clearBurn("d2")

	start := sp.current()
	tcpWalk(b)
	if sp.current() != start {
		t.Fatalf("the first ask of a FRESH round moved the source (%s -> %s): the lap size was carried "+
			"over from the previous outage", start, sp.current())
	}
}
