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

func TestReassessRotationEvents(t *testing.T) {
	b, p := edgeCarrier(t, []string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}})
	count := func(code string) int { return poolEventCount(b, code) }

	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded events = %d, want 1", got)
	}
	if !p.watch.degraded {
		t.Fatal("the watch should be set after losing an edge")
	}

	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded must not repeat, got %d", got)
	}

	p.clearBurn("ip", "1.1.1.1")
	if got := count("restored"); got != 1 {
		t.Fatalf("restored events = %d, want 1", got)
	}
	if p.watch.degraded {
		t.Fatal("the watch should be cleared after recovery")
	}

	b1, p1 := edgeCarrier(t, []string{"9.9.9.9"}, []wsSNIEntry{{host: "a.com"}})
	p1.markSuspect("ip", "9.9.9.9", "test")
	b1.st.mu.Lock()
	for _, e := range b1.st.events {
		if e.Kind == "pool" {
			b1.st.mu.Unlock()
			t.Fatalf("single-ip pool emitted a pool event: %s", e.Code)
		}
	}
	b1.st.mu.Unlock()
}

func TestSelectEntryReassessesRotation(t *testing.T) {
	b, p := edgeCarrier(t, []string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}})
	count := func(code string) int { return poolEventCount(b, code) }

	p.markSuspect("ip", "1.1.1.1", "test")
	if count("degraded") != 1 {
		t.Fatalf("degraded = %d, want 1", count("degraded"))
	}

	if !p.selectEntry("ip", "1.1.1.1") {
		t.Fatal("selectEntry should find 1.1.1.1")
	}
	if count("restored") != 1 {
		t.Fatalf("restored = %d, want 1 (selectEntry must reassess rotation)", count("restored"))
	}
	if p.watch.degraded {
		t.Fatal("rotDegraded must be cleared after the pinned edge's burn was lifted")
	}

	p.markSuspect("ip", "2.2.2.2", "test")
	if count("degraded") != 2 {
		t.Fatalf("degraded = %d, want 2 (a later transition must not be swallowed)", count("degraded"))
	}
}
