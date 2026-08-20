package packet

import (
	"testing"
)

func TestALandingElsewhereDoesNotSettleThePin(t *testing.T) {
	t.Run("direct pool keeps what the pin took", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		p.mu.Lock()
		p.health.burn("a")
		before := *p.health.rec("a")
		p.mu.Unlock()

		if !p.selectEntry("a") {
			t.Fatal("could not pin a")
		}
		p.pinLandedOn("b")
		if !p.isPinned() {
			t.Fatal("a landing somewhere else released the pin")
		}
		p.pinCannotLand("a")
		p.mu.Lock()
		after := p.health.rec("a")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("the pin never landed, yet a's burn is gone — a carrier coming up on a DIFFERENT " +
				"endpoint wiped what the pin took, so the operator's click laundered a dead endpoint")
		}
		if *after != before {
			t.Fatalf("the burn came back changed: %+v, want %+v", *after, before)
		}
	})

	t.Run("edge pool keeps what the pin took", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1"))
		p.mu.Lock()
		p.ipHealth.burn("e2")
		before := *p.ipHealth.rec("e2")
		p.mu.Unlock()

		if !p.selectEntry("ip", "e2") {
			t.Fatal("could not pin e2")
		}
		p.pinLandedOn("e1", "s1")
		if !p.isPinned() {
			t.Fatal("a landing somewhere else released the pin")
		}
		p.pinCannotLand("e2", "")
		p.mu.Lock()
		after := p.ipHealth.rec("e2")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("the pin never landed, yet e2's burn is gone — a carrier coming up on a DIFFERENT " +
				"edge wiped what the pin took")
		}
		if *after != before {
			t.Fatalf("the burn came back changed: %+v, want %+v", *after, before)
		}
	})
}

func TestALandingElsewhereDoesNotDisarmThePin(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0)
		if !p.selectEntry("a") {
			t.Fatal("could not pin a")
		}
		for i := 0; i < 20; i++ {
			p.pinCannotLand("a")
			p.pinLandedOn("b")
			if !p.isPinned() {
				return
			}
		}
		t.Fatal("20 failed attempts on the pinned endpoint and the pin is still in force: every landing " +
			"on some OTHER endpoint reset the count, so the pin can never reach its release")
	})

	t.Run("edge pool", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1"))
		if !p.selectEntry("ip", "e2") {
			t.Fatal("could not pin e2")
		}
		for i := 0; i < 20; i++ {
			p.pinCannotLand("e2", "")
			p.pinLandedOn("e1", "s1")
			if !p.isPinned() {
				return
			}
		}
		t.Fatal("20 failed attempts on the pinned edge and the pin is still in force")
	})
}

func TestRepinningKeepsTheFirstTargetsBurn(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b", "c"}, 0)
		p.mu.Lock()
		p.health.burn("a")
		beforeA := *p.health.rec("a")
		p.mu.Unlock()

		p.selectEntry("a")
		p.selectEntry("b")
		p.pinCannotLand("b")
		p.mu.Lock()
		after := p.health.rec("a")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("a was burned, pinned, then abandoned for b — and its burn is gone. Nothing ever " +
				"tried a, so nothing measured it, and it now reads healthy on the panel")
		}
		if *after != beforeA {
			t.Fatalf("a's burn came back changed: %+v, want %+v", *after, beforeA)
		}
	})

	t.Run("edge pool, second pin abandoned", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1"))
		p.mu.Lock()
		p.ipHealth.burn("e2")
		before := *p.ipHealth.rec("e2")
		p.mu.Unlock()

		p.selectEntry("ip", "e2")
		p.selectEntry("ip", "e3")
		p.pinCannotLand("e3", "")
		p.mu.Lock()
		after := p.ipHealth.rec("e2")
		p.mu.Unlock()
		if after == nil {
			t.Fatal("e2's burn was laundered by a pin that was replaced before it resolved")
		}
		if *after != before {
			t.Fatalf("e2's burn came back changed: %+v, want %+v", *after, before)
		}
	})

	for _, tc := range []struct {
		name string
		run  func(t *testing.T) (before healthRec, after *healthRec, pinned bool)
	}{
		{"direct pool, second pin LANDS", func(t *testing.T) (healthRec, *healthRec, bool) {
			p := NewPeerPool([]string{"a", "b"}, 0)
			p.mu.Lock()
			p.health.burn("a")
			before := *p.health.rec("a")
			p.mu.Unlock()
			p.selectEntry("a")
			p.selectEntry("b")
			p.pinLandedOn("b")
			p.mu.Lock()
			defer p.mu.Unlock()
			return before, p.health.rec("a"), p.pinnedLocked()
		}},
		{"edge pool, second pin LANDS", func(t *testing.T) (healthRec, *healthRec, bool) {
			p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1"))
			p.mu.Lock()
			p.ipHealth.burn("e2")
			before := *p.ipHealth.rec("e2")
			p.mu.Unlock()
			p.selectEntry("ip", "e2")
			p.selectEntry("ip", "e3")
			p.pinLandedOn("e3", "s1")
			p.mu.Lock()
			defer p.mu.Unlock()
			return before, p.ipHealth.rec("e2"), p.pinIP != "" || p.pinSNI != ""
		}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			before, after, pinned := tc.run(t)
			if pinned {
				t.Fatal("the second pin landed and the pool is still pinned")
			}
			if after == nil {
				t.Fatal("the FIRST target's burn is gone. It was never tried, so nothing measured it — " +
					"and because the second pin LANDED there is no abandon left to put it back, so it " +
					"reads healthy on the panel for good")
			}
			if *after != before {
				t.Fatalf("the first target's burn came back changed: %+v, want %+v", *after, before)
			}
		})
	}
}
