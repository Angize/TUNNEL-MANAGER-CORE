package packet

import "testing"

func TestActiveEdgeNotCorruptedByARotationStep(t *testing.T) {
	snis := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis, "")

	ip0, sni0, ok := p.current()
	if !ok {
		t.Fatal("current: pool empty")
	}
	if p.active != "" {
		t.Fatalf("current() must not publish the active edge; got %q", p.active)
	}

	activeCombo := activeLabel(ip0, sni0.host)
	p.setActive(activeCombo)
	if p.active != activeCombo {
		t.Fatalf("setActive: active = %q, want %q", p.active, activeCombo)
	}

	p.advance()
	ipN, sniN, _ := p.current()
	nextCombo := activeLabel(ipN, sniN.host)
	if nextCombo == activeCombo {
		t.Fatal("test setup: the rotation step resolved back to the live edge")
	}
	if p.active != activeCombo {
		t.Fatalf("a rotation step corrupted the active edge: active = %q, want %q", p.active, activeCombo)
	}

	p.setActive(nextCombo)
	if p.active != nextCombo {
		t.Fatalf("after landing: active = %q, want %q", p.active, nextCombo)
	}
}
