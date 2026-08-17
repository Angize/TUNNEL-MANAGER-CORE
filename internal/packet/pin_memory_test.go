package packet

import (
	"path/filepath"
	"testing"
)

// A pin CLEARS its target's burn, because the operator is asking for a fresh try, and both pools remember
// what they cleared so an abandoned pin can put it back. What neither remembered is that the pin's
// bookkeeping is only settled by a landing ON THE PIN. Both pools already compare before releasing the
// pin itself -- and then wipe the memory and the fail counter before that comparison, unconditionally.

// TestALandingElsewhereDoesNotSettleThePin is the case the comparison exists for. tcp can adopt a carrier
// the rotation timer PRE-BUILT, whose endpoint was resolved before the pin existed. The pin correctly
// survives that -- and loses everything that makes it releasable and reversible.
func TestALandingElsewhereDoesNotSettleThePin(t *testing.T) {
	t.Run("direct pool keeps what the pin took", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
		p.mu.Lock()
		p.health.burn("a")
		before := *p.health.rec("a")
		p.mu.Unlock()

		if !p.selectEntry("a") {
			t.Fatal("could not pin a")
		}
		p.pinLandedOn("b") // a carrier came up on b — NOT the operator's pick
		if !p.isPinned() {
			t.Fatal("a landing somewhere else released the pin")
		}
		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("a")
		}
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
		p := newWSPool([]string{"e1", "e2"}, snis("s1"), filepath.Join(t.TempDir(), "st.json"))
		p.mu.Lock()
		p.ipHealth.burn("e2")
		before := *p.ipHealth.rec("e2")
		p.mu.Unlock()

		if !p.selectEntry("ip", "e2") {
			t.Fatal("could not pin e2")
		}
		p.pinApplied("e1", "s1") // a carrier resolved before the pin came up on e1
		if !p.isPinned() {
			t.Fatal("a landing somewhere else released the pin")
		}
		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("e2", "")
		}
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

// TestALandingElsewhereDoesNotDisarmThePin is the worse half of the same defect. A pin ends on EVIDENCE:
// pinFailRelease attempts that did not come up. Resetting that counter on a landing the pin did not ask
// for means a carrier repeatedly coming up somewhere else keeps the counter at zero forever, and the pin
// onto a genuinely dead entry NEVER self-releases -- which is the exact "held hostage by a pin" the
// counter was added to prevent.
func TestALandingElsewhereDoesNotDisarmThePin(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
		if !p.selectEntry("a") {
			t.Fatal("could not pin a")
		}
		for i := 0; i < 20; i++ {
			p.pinAttemptFailed("a") // the pinned endpoint will not come up
			p.pinLandedOn("b")      // ...while a pre-built carrier keeps landing on b
			if !p.isPinned() {
				return // released as it should
			}
		}
		t.Fatal("20 failed attempts on the pinned endpoint and the pin is still in force: every landing " +
			"on some OTHER endpoint reset the count, so the pin can never reach its release")
	})

	t.Run("edge pool", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1"), filepath.Join(t.TempDir(), "st.json"))
		if !p.selectEntry("ip", "e2") {
			t.Fatal("could not pin e2")
		}
		for i := 0; i < 20; i++ {
			p.pinAttemptFailed("e2", "")
			p.pinApplied("e1", "s1")
			if !p.isPinned() {
				return
			}
		}
		t.Fatal("20 failed attempts on the pinned edge and the pin is still in force")
	})
}

// TestRepinningKeepsTheFIRSTTargetsBurn: the operator changes their mind before the first jump resolves.
// The edge pool keeps one saved record PER ENTRY and puts them all back; the direct pool kept a single
// unkeyed record, so the second pin overwrote the first and the first target's burn was laundered with
// nothing left to restore it. Same button, same expectation, two different answers.
func TestRepinningKeepsTheFirstTargetsBurn(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b", "c"}, 0, filepath.Join(t.TempDir(), "p.json"))
		p.mu.Lock()
		p.health.burn("a")
		beforeA := *p.health.rec("a")
		p.mu.Unlock()

		p.selectEntry("a")
		p.selectEntry("b") // changed their mind before a resolved
		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("b")
		}
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
		p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1"), filepath.Join(t.TempDir(), "st.json"))
		p.mu.Lock()
		p.ipHealth.burn("e2")
		before := *p.ipHealth.rec("e2")
		p.mu.Unlock()

		p.selectEntry("ip", "e2")
		p.selectEntry("ip", "e3")
		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("e3", "")
		}
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

	// The abandon path above is covered by the edge pool's restore-everything sweep whichever way the
	// replacement is handled, so it cannot tell the two apart. The LANDING path can: settling a pin
	// settles the entry it landed on and nothing else, so a record the operator moved off is left in the
	// map with nothing that will ever put it back.
	for _, tc := range []struct {
		name string
		run  func(t *testing.T) (before healthRec, after *healthRec, pinned bool)
	}{
		{"direct pool, second pin LANDS", func(t *testing.T) (healthRec, *healthRec, bool) {
			p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
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
			p := newWSPool([]string{"e1", "e2", "e3"}, snis("s1"), filepath.Join(t.TempDir(), "st.json"))
			p.mu.Lock()
			p.ipHealth.burn("e2")
			before := *p.ipHealth.rec("e2")
			p.mu.Unlock()
			p.selectEntry("ip", "e2")
			p.selectEntry("ip", "e3")
			p.pinApplied("e3", "s1")
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
