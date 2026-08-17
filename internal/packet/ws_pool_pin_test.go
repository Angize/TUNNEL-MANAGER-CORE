package packet

import "testing"

// TestPinHeldUntilAppliedThenReleased locks in the pin robustness fix: a manual pin FORCES the
// exact edge (even while it is momentarily unreachable, e.g. during an origin blip) until the
// carrier actually lands on it, then releases immediately so auto-rotation resumes — instead of the
// old 20s wall-clock one-shot that expired before a down origin could recover.
func TestPinHeldUntilAppliedThenReleased(t *testing.T) {
	snis := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis, "")

	// Drive a fake clock so the test never depends on wall time.
	var clk int64 = 1000
	p.now = func() int64 { return clk }

	// Operator pins IP 2.2.2.2. current() must FORCE it on every call while unapplied — modelling an
	// outage where the pinned edge can't be dialed yet: the pin must not drift or expire early.
	if !p.selectEntry("ip", "2.2.2.2") {
		t.Fatal("selectEntry: unknown key")
	}
	for i := 0; i < 5; i++ {
		clk += 30 // 150s later — would have blown the old 20s TTL
		ip, _, ok := p.current()
		if !ok || ip != "2.2.2.2" {
			t.Fatalf("pin not held while unapplied at +%ds: ip=%q", (i+1)*30, ip)
		}
	}

	// The carrier finally lands on the pinned edge — the pin is consumed at once.
	p.pinApplied("2.2.2.2", "a.example")
	if p.pinIP != "" {
		t.Fatalf("pin not cleared after apply: pinIP=%q", p.pinIP)
	}

	// A non-matching apply must NOT clear a live pin (only the exact edge releases it).
	if !p.selectEntry("sni", "b.example") {
		t.Fatal("selectEntry sni: unknown key")
	}
	p.pinApplied("9.9.9.9", "a.example") // wrong IP and SNI
	if p.pinSNI != "b.example" {
		t.Fatalf("non-matching apply wrongly cleared the SNI pin: pinSNI=%q", p.pinSNI)
	}
	p.pinApplied("1.1.1.1", "b.example") // SNI matches -> that axis releases
	if p.pinSNI != "" {
		t.Fatalf("matching SNI apply did not clear pin: pinSNI=%q", p.pinSNI)
	}

	// With NO apply, the pin releases on the core's own failed attempts, so a permanently-dead pinned
	// edge cannot strand the tunnel. No clock is involved — that is the whole point.
	if !p.selectEntry("ip", "1.1.1.1") {
		t.Fatal("selectEntry: unknown key")
	}
	for i := 0; i < pinFailRelease; i++ {
		p.pinAttemptFailed("1.1.1.1", "")
	}
	if _, _, ok := p.current(); !ok {
		t.Fatal("current: pool empty")
	}
	if p.pinIP != "" {
		t.Fatalf("pin did not self-release past the TTL ceiling: pinIP=%q", p.pinIP)
	}
}
