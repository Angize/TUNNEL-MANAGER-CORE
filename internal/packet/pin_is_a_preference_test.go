package packet

import (
	"path/filepath"
	"testing"
)

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

func TestPinAbsorbsExactlyOneSecondOpinion_TCP(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{isClient: true}
	b.SetPeerPool(NewPeerPool([]string{"d1", "d2"}, 0, filepath.Join(dir, "d.json")))
	b.SetSourcePool(NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")))
	if !b.pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	for i := 1; i < pinFailRelease; i++ {
		if tcpWalk(b) {
			t.Fatalf("verdict %d of %d already burned — a pin must absorb the first ones", i, pinFailRelease)
		}
		if !b.pp.isPinned() {
			t.Fatalf("verdict %d of %d released the pin", i, pinFailRelease)
		}
	}
	burned := tcpWalk(b)
	if b.pp.isPinned() {
		t.Fatalf("after %d proven-dead verdicts the pin still freezes failover — this is the whole bug: "+
			"udp/raw/flux recovered from identical evidence while tcp stayed down for the rest of pinTTL",
			pinFailRelease)
	}
	if !burned {
		t.Fatal("the pin released but the pool did not burn and advance")
	}
}

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

func TestPinCountResetsBetweenPins(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{isClient: true}
	b.SetPeerPool(NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json")))
	b.SetSourcePool(NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")))

	if !b.pp.selectEntry("d2") {
		t.Fatal("could not pin")
	}
	if tcpWalk(b) {
		t.Fatal("the first verdict under a pin must be absorbed")
	}
	b.pp.releasePin()

	tcpWalk(b)

	if !b.pp.selectEntry("d3") {
		t.Fatal("could not re-pin")
	}
	for i := 1; i < pinFailRelease; i++ {
		if tcpWalk(b) || !b.pp.isPinned() {
			t.Fatalf("the fresh pin broke on verdict %d of %d — it inherited the earlier pin's count",
				i, pinFailRelease)
		}
	}
}

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
		p.pinAttemptFailed("a")
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
		clk += 86400
		if !p.isPinned() {
			t.Fatal("the clock released a pin that nothing had disproven")
		}
	})
}

func TestAHealthySessionEndsTheRound(t *testing.T) {
	t.Run("the direct pool's counters", func(t *testing.T) {
		dir := t.TempDir()
		b := &TCP{isClient: true}
		b.SetPeerPool(NewPeerPool([]string{"d1", "d2", "d3"}, 0, filepath.Join(dir, "d.json")))
		b.SetSourcePool(NewPeerPool([]string{"s1", "s2"}, 0, filepath.Join(dir, "s.json")))
		if !b.pp.selectEntry("d2") {
			t.Fatal("could not pin")
		}
		tcpWalk(b)
		b.rc.od.rot = 3
		b.endRound()
		if got := b.rc.pinFails; got != 0 {
			t.Fatalf("the pin's allowance survived a healthy session (pinFails=%d)", got)
		}
		if got := b.rc.od.rot; got != 0 {
			t.Fatalf("the lap survived a healthy session (rot=%d)", got)
		}
	})
	t.Run("the edge pool's counters", func(t *testing.T) {
		p := newWSPool([]string{"e1", "e2"}, snis("s1", "s2", "s3"), filepath.Join(t.TempDir(), "st.json"))
		b := &TCP{pool: p}
		b.odEdge.rot = 2
		b.pinFails.Store(1)
		b.endRound()
		if got := b.odEdge.rot; got != 0 {
			t.Fatalf("the edge pool's half-walked lap survived a healthy session (rot=%d) — the next "+
				"outage would convict the edge after one verdict", got)
		}
		if got := b.pinFails.Load(); got != 0 {
			t.Fatalf("the edge pool's pin allowance survived a healthy session (pinFails=%d)", got)
		}
	})
}
