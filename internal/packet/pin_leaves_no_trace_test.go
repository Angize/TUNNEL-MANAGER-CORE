package packet

import (
	"path/filepath"
	"testing"
)

// A pin is a QUESTION, not an answer: "try this one." Until it is answered, the pool must not have been
// changed by the asking. Two ways that went wrong, one per pool.

// TestAnAbandonedPinPutsTheBurnBack: pinning CLEARS the entry's burn, because the operator is asking for
// a fresh try and a burned entry would otherwise be skipped the moment the pin ends. But that clear is
// not a verdict. A pin that never lands must put back exactly what it took, or a jump onto a dead entry
// leaves it looking HEALTHY on the panel -- the operator's own click having laundered it.
func TestAnAbandonedPinPutsTheBurnBack(t *testing.T) {
	t.Run("direct pool", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
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

		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("b")
		}
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
		p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), filepath.Join(t.TempDir(), "st.json"))
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

		for i := 0; i < pinFailRelease; i++ {
			p.pinAttemptFailed("e2", "")
		}
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
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
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

// TestTheEdgePoolsActiveFollowsThePin is the other half, and the one that burned an innocent edge. The
// node keys its verdict on the pool's published `active`. The direct pool publishes its CURSOR, which a
// pin moves; the edge pool published a string only a SUCCESSFUL dial ever wrote — so between the pin and
// the first connection it still named the PREVIOUS edge. A verdict measured during that window then
// matched the old combination and condemned it, for a jump onto something else entirely.
func TestTheEdgePoolsActiveFollowsThePin(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("s1"), filepath.Join(t.TempDir(), "st.json"))
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host)) // the tunnel is up on e1
	if got, _ := p.activeCombo(); got != "e1" {
		t.Fatalf("setup: active is %q, want e1", got)
	}

	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not pin e2")
	}
	got, _ := p.activeCombo()
	if got == "e1" {
		t.Fatal("active still names e1 after pinning e2 — a verdict arriving now would burn the edge the " +
			"tunnel just left, not the one it is attempting")
	}
	if got != "e2" {
		t.Fatalf("active is %q after pinning e2", got)
	}

	// ...and it does NOT roll back when the pin is abandoned: the pool moves FORWARD to whatever
	// current() picks next, never back onto the combination nothing measured.
	for i := 0; i < pinFailRelease; i++ {
		p.pinAttemptFailed("e2", "")
	}
	if p.isPinned() {
		t.Fatal("the pin should have been released")
	}
}
