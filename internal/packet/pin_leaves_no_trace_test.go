package packet

import (
	"testing"
)

func TestAnAbandonedPinPutsTheBurnBack(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		p.mu.Lock()
		p.health.burn("b")
		before := *p.health.rec("b")
		p.mu.Unlock()

		if !p.selectEntry("b") {
			t.Fatal("could not pin")
		}
		p.mu.Lock()
		cleared := p.health.healthy("b")
		p.mu.Unlock()
		if !cleared {
			t.Fatal("the pin must clear the burn, or the entry is skipped the moment the pin ends")
		}

		p.pinCannotLand("b")
		p.mu.Lock()
		after := p.health.rec("b")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("the pin never landed and the burn is gone — a dead entry now reads as healthy")
		}
		if *after != before {
			t.Fatalf("the burn came back changed: %+v, want %+v — an abandoned pin must be a no-op", *after, before)
		}
	})

	t.Run("edge pool", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"))
		p.mu.Lock()
		p.ipHealth.burn("e2")
		before := *p.ipHealth.rec("e2")
		p.mu.Unlock()

		if !p.selectEntry("ip", "e2") {
			t.Fatal("could not pin")
		}
		p.mu.Lock()
		cleared := p.ipHealth.healthy("e2")
		p.mu.Unlock()
		if !cleared {
			t.Fatal("the pin must clear the burn")
		}

		p.pinCannotLand("e2")
		p.mu.Lock()
		after := p.ipHealth.rec("e2")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("the pin never landed and the burn is gone — a dead edge now reads as healthy")
		}
		if *after != before {
			t.Fatalf("the burn came back changed: %+v, want %+v", *after, before)
		}
	})

	t.Run("a pin that LANDS keeps the clear", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		p.mu.Lock()
		p.health.burn("b")
		p.mu.Unlock()
		if !p.selectEntry("b") {
			t.Fatal("could not pin")
		}
		p.pinLandedOn("b")
		p.mu.Lock()
		healthy := p.health.healthy("b")
		p.mu.Unlock()
		if !healthy {
			t.Fatal("it connected — that IS the entry proving itself, so the burn must stay gone")
		}
	})
}

// While the carrier is DOWN the published pair is the cursor, so it follows the pin at once. A verdict
// arriving in that window must name the edge the tunnel is attempting, not the one it just left.
func TestThePublishedPairFollowsThePinWhileDown(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("s1"))
	b.pretendDown()
	if low, _ := b.livePairNow(); low != "e1" {
		t.Fatalf("setup: the pair names %q, want e1", low)
	}

	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not pin e2")
	}
	low, _ := b.livePairNow()
	if low == "e1" {
		t.Fatal("the pair still names e1 after pinning e2 — a verdict arriving now would burn the edge " +
			"the tunnel just left, not the one it is attempting")
	}
	if low != "e2" {
		t.Fatalf("the pair names %q after pinning e2", low)
	}
	if got := b.readStatus(t).Pair.Low; got != "e2" {
		t.Fatalf("the status file the node reads still says %q", got)
	}

	p.pinCannotLand("e2")
	if p.isPinned() {
		t.Fatal("the pin should have been released")
	}
}
