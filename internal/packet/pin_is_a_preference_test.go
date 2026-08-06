package packet

import (
	"path/filepath"
	"testing"
	"time"
)

// A pin means the same thing on every carrier: the operator's PREFERENCE, held against the probe until
// the probe has said the same thing pinFailRelease times, then released so the tunnel recovers.
//
// The three carriers reach that rule by three different functions, and before this they disagreed:
// udp/raw/flux counted (rotationController.fail), tcp ignored the verdict outright for the whole of
// pinTTL, and the CDN pool broke the pin on the FIRST verdict. Same evidence, three outcomes.
//
// So each case drives its own real entry point and asserts the identical schedule. A carrier that ever
// needs its own numbers here has drifted back out.

// TestPinAbsorbsExactlyOneSecondOpinion_Direct is the reference the other two are held to.
func TestPinAbsorbsExactlyOneSecondOpinion_Direct(t *testing.T) {
	dir := t.TempDir()
	dst := NewPeerPool([]string{"d1", "d2"}, true, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool([]string{"s1", "s2"}, true, 0, filepath.Join(dir, "s.json"))
	rc := newRotationController(dst, src)
	if !dst.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	moved := 0
	rot := func(bool) { moved++ }

	for i := 1; i < pinFailRelease; i++ {
		rc.fail(rot, rot)
		if moved != 0 {
			t.Fatalf("verdict %d of %d already moved the pool — a pin must absorb the first ones", i, pinFailRelease)
		}
		if !dst.isPinned() {
			t.Fatalf("verdict %d of %d released the pin", i, pinFailRelease)
		}
	}
	rc.fail(rot, rot)
	if dst.isPinned() {
		t.Fatalf("after %d proven-dead verdicts the pin still holds the tunnel", pinFailRelease)
	}
	if moved == 0 {
		t.Fatal("the pin released but the pool did not move off the blocked endpoint")
	}
}

// TestPinAbsorbsExactlyOneSecondOpinion_TCP: the direct tcp carrier reaches the odometer through
// burnAdvance, not through rotationController, and used to freeze outright instead of counting.
func TestPinAbsorbsExactlyOneSecondOpinion_TCP(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2"}, true, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, true, 0, filepath.Join(dir, "s.json")),
	}
	if !b.pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	for i := 1; i < pinFailRelease; i++ {
		if _, moved := b.burnAdvance(true); moved {
			t.Fatalf("verdict %d of %d already burned — a pin must absorb the first ones", i, pinFailRelease)
		}
		if !b.pp.isPinned() {
			t.Fatalf("verdict %d of %d released the pin", i, pinFailRelease)
		}
	}
	_, moved := b.burnAdvance(true)
	if b.pp.isPinned() {
		t.Fatalf("after %d proven-dead verdicts the pin still freezes failover — this is the whole bug: "+
			"udp/raw/flux recovered from identical evidence while tcp stayed down for the rest of pinTTL",
			pinFailRelease)
	}
	if !moved {
		t.Fatal("the pin released but the pool did not burn and advance")
	}
}

// TestPinAbsorbsExactlyOneSecondOpinion_CDN: the edge pool used to drop the pin as it burned, so ONE
// measurement overrode the operator — the opposite failure from tcp's, and just as inconsistent.
func TestPinAbsorbsExactlyOneSecondOpinion_CDN(t *testing.T) {
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), true, filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{pool: p}
	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not pin")
	}
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))

	for i := 1; i < pinFailRelease; i++ {
		if b.burnAdvanceWS(sni.host) {
			t.Fatalf("verdict %d of %d already burned — a pin must absorb the first ones", i, pinFailRelease)
		}
		if !p.isPinned() {
			t.Fatalf("verdict %d of %d released the pin", i, pinFailRelease)
		}
		if !p.sniHealth.healthy(sni.host) {
			t.Fatalf("verdict %d of %d burned the SNI while the pin was still in force", i, pinFailRelease)
		}
	}
	if !b.burnAdvanceWS(sni.host) {
		t.Fatal("the pin absorbed its second opinion and the pool still did not burn")
	}
	if p.isPinned() {
		t.Fatalf("after %d proven-dead verdicts the pin still holds the edge", pinFailRelease)
	}
	if p.sniHealth.healthy(sni.host) {
		t.Fatal("the pin released but nothing was burned")
	}
}

// TestPinCountResetsBetweenPins: the tally is per PIN, not per lifetime. A round that arrives while
// nothing is pinned clears it, so the operator's NEXT pin gets its own full allowance. Without that, a
// pin placed after an earlier one had already absorbed a verdict would break on its very first.
func TestPinCountResetsBetweenPins(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, true, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, true, 0, filepath.Join(dir, "s.json")),
	}
	// A first pin absorbs one verdict, then the operator drops it.
	if !b.pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	if _, moved := b.burnAdvance(true); moved {
		t.Fatal("the first verdict under a pin must be absorbed")
	}
	b.pp.releasePin()

	// An UNPINNED round: this is what clears the tally.
	b.burnAdvance(true)

	// A fresh pin must get the full allowance again.
	if !b.pp.selectEntry("d3") {
		t.Fatal("could not re-pin")
	}
	for i := 1; i < pinFailRelease; i++ {
		if _, moved := b.burnAdvance(true); moved || !b.pp.isPinned() {
			t.Fatalf("the fresh pin broke on verdict %d of %d — it inherited the earlier pin's count",
				i, pinFailRelease)
		}
	}
}

// TestPinnedIsNotPinnedOnceItLapses guards the input the whole rule reads: an expired pin is not a pin,
// so a lapsed one must not go on absorbing verdicts.
func TestPinnedIsNotPinnedOnceItLapses(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, filepath.Join(t.TempDir(), "p.json"))
	clk := time.Now().Unix()
	p.now = func() int64 { return clk }
	if !p.selectEntry("b") {
		t.Fatal("could not pin")
	}
	if !p.isPinned() {
		t.Fatal("a fresh pin does not report as pinned")
	}
	clk += pinTTL + 1
	if p.isPinned() {
		t.Fatal("a lapsed pin still reports as pinned, so it would keep absorbing verdicts forever")
	}
}
