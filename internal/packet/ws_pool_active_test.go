package packet

import "testing"

// TestActiveEdgeNotCorruptedByARotationStep locks in the rule that the status file's "active edge" must
// reflect the carrier ACTUALLY carrying data, never the edge the rotation cursor happens to be sitting on.
// current() picks an edge but must NOT publish it; only setActive does. Otherwise a rotation step taken
// while the old carrier is still live clobbers the active and the panel's auto-switch log goes wrong or
// silent.
func TestActiveEdgeNotCorruptedByARotationStep(t *testing.T) {
	snis := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis, "")

	// current() picks an edge but must leave the published active empty.
	ip0, sni0, ok := p.current()
	if !ok {
		t.Fatal("current: pool empty")
	}
	if p.active != "" {
		t.Fatalf("current() must not publish the active edge; got %q", p.active)
	}

	// The client establishes the carrier on that edge and publishes it.
	activeCombo := activeLabel(ip0, sni0.host)
	p.setActive(activeCombo)
	if p.active != activeCombo {
		t.Fatalf("setActive: active = %q, want %q", p.active, activeCombo)
	}

	// The rotation timer steps the cursor and the next dial asks current() again. Until that dial
	// LANDS, the published active must still name the edge the tunnel is carrying on.
	p.advance()
	ipN, sniN, _ := p.current()
	nextCombo := activeLabel(ipN, sniN.host)
	if nextCombo == activeCombo {
		t.Fatal("test setup: the rotation step resolved back to the live edge")
	}
	if p.active != activeCombo {
		t.Fatalf("a rotation step corrupted the active edge: active = %q, want %q", p.active, activeCombo)
	}

	// Once the new carrier lands, it becomes the live active and IS published.
	p.setActive(nextCombo)
	if p.active != nextCombo {
		t.Fatalf("after landing: active = %q, want %q", p.active, nextCombo)
	}
}
