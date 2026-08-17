package packet

import (
	"path/filepath"
	"testing"
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
	dst := NewPeerPool([]string{"d1", "d2"}, 0, filepath.Join(dir, "d.json"))
	src := NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json"))
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
		pp: NewPeerPool([]string{"d1", "d2"}, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")),
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
	p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2"), filepath.Join(t.TempDir(), "st.json"))
	b := &TCP{pool: p}
	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not pin")
	}
	ip, sni, _ := p.current()
	p.setActive(activeLabel(ip, sni.host))

	for i := 1; i < pinFailRelease; i++ {
		if b.burnAdvanceWS(ip, sni.host) {
			t.Fatalf("verdict %d of %d already burned — a pin must absorb the first ones", i, pinFailRelease)
		}
		if !p.isPinned() {
			t.Fatalf("verdict %d of %d released the pin", i, pinFailRelease)
		}
		if !p.sniHealth.healthy(sni.host) {
			t.Fatalf("verdict %d of %d burned the SNI while the pin was still in force", i, pinFailRelease)
		}
	}
	if !b.burnAdvanceWS(ip, sni.host) {
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
		pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json")),
		sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")),
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

// TestAPinEndsOnEvidenceNeverOnAClock: there is no TTL. A pin ends exactly two ways — the carrier lands
// on it, or the core's own attempts disprove it — and both are things that were MEASURED. A clock could
// only ever guess, and it guessed badly in both directions: too short froze a jump that was still
// connecting, too long stranded the tunnel on a dead pick.
func TestAPinEndsOnEvidenceNeverOnAClock(t *testing.T) {
	t.Run("it lands", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
		if !p.selectEntry("b") || !p.isPinned() {
			t.Fatal("could not pin")
		}
		p.pinLandedOn("b")
		if p.isPinned() {
			t.Fatal("a landed pin must release at once")
		}
	})
	t.Run("it cannot land", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
		if !p.selectEntry("b") || !p.isPinned() {
			t.Fatal("could not pin")
		}
		p.pinAttemptFailed("a") // a failure on a DIFFERENT endpoint proves nothing about this pin
		for i := 1; i < pinFailRelease; i++ {
			p.pinAttemptFailed("b")
			if !p.isPinned() {
				t.Fatalf("attempt %d of %d released it — one failure is not evidence", i, pinFailRelease)
			}
		}
		p.pinAttemptFailed("b")
		if p.isPinned() {
			t.Fatalf("after %d failed attempts on the pinned endpoint the pin must go", pinFailRelease)
		}
	})
	t.Run("time alone does nothing", func(t *testing.T) {
		p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(t.TempDir(), "p.json"))
		clk := int64(1000)
		p.now = func() int64 { return clk }
		if !p.selectEntry("b") {
			t.Fatal("could not pin")
		}
		clk += 86400 // a whole day
		if !p.isPinned() {
			t.Fatal("the clock released a pin that nothing had disproven")
		}
	})
}

// TestAHealthySessionEndsTheRound is the other half of "consecutive": the counters a round feeds -- the
// pin's allowance and the lap it is walking -- are per OUTAGE, and a carrier that came up healthy ends
// it. udp/raw/flux get this from rotationController.success; tcp and the edge pool reach the same reset
// through succeedBoth, which used to be wired on the direct branch ONLY. The edge pool's own counters
// therefore ran for the life of the process: a round that burned two of three SNIs an hour ago would
// make the NEXT outage convict the edge after one verdict.
func TestAHealthySessionEndsTheRound(t *testing.T) {
	t.Run("the direct pool's counters", func(t *testing.T) {
		dir := t.TempDir()
		b := &TCP{
			pp: NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json")),
			sp: NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")),
		}
		if !b.pp.selectEntry("d2") {
			t.Fatal("could not pin")
		}
		b.burnAdvance(true) // absorbed; the allowance is now partly spent
		b.destRot.Store(3)  // ...and a lap is half walked
		b.endRound()
		if got := b.pinFails.Load(); got != 0 {
			t.Fatalf("the pin's allowance survived a healthy session (pinFails=%d)", got)
		}
		if got := b.destRot.Load(); got != 0 {
			t.Fatalf("the lap survived a healthy session (destRot=%d)", got)
		}
	})
	t.Run("the edge pool's counters", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2", "s3"), filepath.Join(t.TempDir(), "st.json"))
		b := &TCP{pool: p}
		b.sniRot.Store(2)
		b.pinFails.Store(1)
		b.endRound()
		if got := b.sniRot.Load(); got != 0 {
			t.Fatalf("the edge pool's half-walked lap survived a healthy session (sniRot=%d) — the next "+
				"outage would convict the edge after one verdict", got)
		}
		if got := b.pinFails.Load(); got != 0 {
			t.Fatalf("the edge pool's pin allowance survived a healthy session (pinFails=%d)", got)
		}
	})
}
