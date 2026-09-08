package packet

import "testing"

func poolEventCount(b *TCP, code string) int {
	b.st.mu.Lock()
	defer b.st.mu.Unlock()
	n := 0
	for _, e := range b.st.events {
		if e.Kind == "pool" && e.Code == code {
			n++
		}
	}
	return n
}

func rotDegraded(p *PeerPool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watch.degraded
}

func TestReassessRotationEvents(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}})
	count := func(code string) int { return poolEventCount(b, code) }

	pp.markSuspect("1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded events = %d, want 1", got)
	}
	if !rotDegraded(pp) {
		t.Fatal("the watch should be set after losing an edge")
	}

	pp.markSuspect("1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded must not repeat, got %d", got)
	}

	pp.clearBurn("1.1.1.1")
	if got := count("restored"); got != 1 {
		t.Fatalf("restored events = %d, want 1", got)
	}
	if rotDegraded(pp) {
		t.Fatal("the watch should be cleared after recovery")
	}
}

// An axis of one is condemned like any other -- what it does not get is a rotation line, because there
// is no rotation to lose. The burn is what the operator acts on; "degraded 1/1" would be noise.
func TestAOneEntryAxisRaisesNoRotationLine(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"9.9.9.9"}, []wsSNIEntry{{host: "a.com"}})
	pp.markSuspect("9.9.9.9", "test")

	burns := 0
	b.st.mu.Lock()
	for _, e := range b.st.events {
		if e.Kind == "pool" {
			b.st.mu.Unlock()
			t.Fatalf("single-ip pool emitted a pool event: %s %s", e.Code, e.Detail)
		}
		if e.Kind == "burn" && e.Detail == "ip:9.9.9.9" {
			burns++
		}
	}
	b.st.mu.Unlock()

	if burns != 1 {
		t.Fatalf("burn events for the lone edge = %d, want 1", burns)
	}
	if pp.burnCount() != 1 {
		t.Fatalf("burnCount = %d, want 1 -- the only edge is still condemned", pp.burnCount())
	}
}

func TestSelectEntryReassessesRotation(t *testing.T) {
	b, pp, _ := edgeCarrier(t, []string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}})
	count := func(code string) int { return poolEventCount(b, code) }

	pp.markSuspect("1.1.1.1", "test")
	if count("degraded") != 1 {
		t.Fatalf("degraded = %d, want 1", count("degraded"))
	}
	if got := pp.current(); got == "1.1.1.1" {
		t.Fatalf("the pool is still on %q after burning it", got)
	}

	if !pp.selectEntry("1.1.1.1") {
		t.Fatal("selectEntry should move the cursor back onto the burned edge it names")
	}
	if count("restored") != 1 {
		t.Fatalf("restored = %d, want 1 (selectEntry must reassess rotation)", count("restored"))
	}
	if rotDegraded(pp) {
		t.Fatal("the watch must be cleared after the pinned edge's burn was lifted")
	}

	pp.markSuspect("2.2.2.2", "test")
	if count("degraded") != 2 {
		t.Fatalf("degraded = %d, want 2 (a later transition must not be swallowed)", count("degraded"))
	}
}
