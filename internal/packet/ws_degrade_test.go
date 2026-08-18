package packet

import "testing"

func TestReassessRotationEvents(t *testing.T) {
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}}, "")

	count := func(code string) int {
		p.mu.Lock()
		defer p.mu.Unlock()
		n := 0
		for _, e := range p.events {
			if e.Kind == "pool" && e.Code == code {
				n++
			}
		}
		return n
	}

	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded events = %d, want 1", got)
	}
	if !p.rotDegraded {
		t.Fatal("rotDegraded should be set after losing an edge")
	}

	p.markSuspect("ip", "1.1.1.1", "test")
	if got := count("degraded"); got != 1 {
		t.Fatalf("degraded must not repeat, got %d", got)
	}

	p.retestResult("ip", "1.1.1.1", true)
	if got := count("restored"); got != 1 {
		t.Fatalf("restored events = %d, want 1", got)
	}
	if p.rotDegraded {
		t.Fatal("rotDegraded should be cleared after recovery")
	}

	p1 := newWSPool([]string{"9.9.9.9"}, []wsSNIEntry{{host: "a.com"}}, "")
	p1.markSuspect("ip", "9.9.9.9", "test")
	p1.mu.Lock()
	for _, e := range p1.events {
		if e.Kind == "pool" {
			p1.mu.Unlock()
			t.Fatalf("single-ip pool emitted a pool event: %s", e.Code)
		}
	}
	p1.mu.Unlock()
}

func TestSelectEntryReassessesRotation(t *testing.T) {
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, []wsSNIEntry{{host: "a.com"}}, "")
	count := func(code string) int {
		p.mu.Lock()
		defer p.mu.Unlock()
		n := 0
		for _, e := range p.events {
			if e.Kind == "pool" && e.Code == code {
				n++
			}
		}
		return n
	}

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
	if p.rotDegraded {
		t.Fatal("rotDegraded must be cleared after the pinned edge's burn was lifted")
	}

	p.markSuspect("ip", "2.2.2.2", "test")
	if count("degraded") != 2 {
		t.Fatalf("degraded = %d, want 2 (a later transition must not be swallowed)", count("degraded"))
	}
}
