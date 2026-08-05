package packet

import (
	"path/filepath"
	"testing"
	"time"
)

// nodeFail burns the pool's ACTIVE endpoint the way the node's fail command does, and returns the
// endpoint that was condemned. On a direct pool this is the ONLY thing that burns.
func nodeFail(p *PeerPool) string {
	gone := p.current()
	p.fail()
	return gone
}

// TestNothingButTheNodeClearsABurn is the rule itself. A burn stands until the node's tun probe says
// the tunnel is carrying (cmdOK, which lands here as clearBurn). A live carrier does not clear it: a
// frame that came back proves an endpoint answered US, and an endpoint can answer everything we send
// while carrying nothing — which is exactly what 5.75.197.201 does from Iran.
func TestNothingButTheNodeClearsABurn(t *testing.T) {
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	gone := nodeFail(p)
	if gone != "a" {
		t.Fatalf("setup: expected to burn a, got %s", gone)
	}
	// Put the cursor back ON the burned endpoint — the 3-minute rotation lands there, a frame comes
	// back, and THAT is the shape that used to wipe the burn one second later.
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	rc := newRotationController(p, nil)
	rc.success() // the carrier is up and answering on it — this must change nothing about the burn
	p.mu.Lock()
	stillBurned := p.health["a"] != nil
	p.mu.Unlock()
	if !stillBurned {
		t.Fatal("a live carrier cleared a burn — only the tun probe may")
	}
	if p.clearBurn("b") {
		t.Fatal("an OK for a different endpoint must not clear this one")
	}
	p.mu.Lock()
	stillBurned = p.health["a"] != nil
	p.mu.Unlock()
	if !stillBurned {
		t.Fatal("an OK keyed elsewhere cleared the wrong endpoint")
	}
	if !p.clearBurn("a") {
		t.Fatal("the node's OK must clear the burn it names")
	}
	if p.clearBurn("a") {
		t.Fatal("a second OK is not a second heal — no duplicate event")
	}
}

// TestABurnedEndpointIsSelectableOnceDue covers how a burned endpoint gets retried at all. There is no
// out-of-band prober: the only way to test a destination is to USE it, so the backoff decides when the
// rotation may pick it up again and the node's probe decides what happens next.
func TestABurnedEndpointIsSelectableOnceDue(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	nodeFail(p) // burns a, cursor moves to b
	if _, moved := p.rotateOnce(); moved {
		t.Fatal("a burn whose backoff is still running must not be selected")
	}
	clk += suspectBackoff[0]
	if _, moved := p.rotateOnce(); !moved || p.current() != "a" {
		t.Fatalf("once its backoff elapsed the rotation must retry it, got %q", p.current())
	}
}

// TestTheLadderDeepensWhileOnlyTheNodeSpeaks walks the whole schedule. Each verdict from the node pushes
// the next retry further out, so an endpoint that keeps failing is tried rarely rather than every cycle;
// and one OK wipes the record, so a genuine recovery starts clean.
func TestTheLadderDeepensWhileOnlyTheNodeSpeaks(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	for i, want := range suspectBackoff {
		p.mu.Lock()
		p.cur, p.chosen = 0, ""
		p.mu.Unlock()
		p.fail()
		p.mu.Lock()
		r := p.health["a"]
		fails, next := r.fails, r.nextRetest
		p.mu.Unlock()
		if fails != i || next != clk+want {
			t.Fatalf("verdict #%d should sit at step %d (+%ds), got fails=%d next=+%d", i+1, i, want, fails, next-clk)
		}
	}
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.fail()
	p.mu.Lock()
	state, next := p.health["a"].state, p.health["a"].nextRetest
	p.mu.Unlock()
	if state != stateDead || next != clk+deadRetest {
		t.Fatalf("past the last step it must go dead at +%ds, got %s at +%d", deadRetest, state, next-clk)
	}
	if !p.clearBurn("a") {
		t.Fatal("an OK must clear even a dead endpoint")
	}
	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.fail()
	p.mu.Lock()
	fails := p.health["a"].fails
	p.mu.Unlock()
	if fails != 0 {
		t.Fatalf("after an OK the ladder starts over, got fails=%d", fails)
	}
}

// TestProbeNowMakesEveryBurnSelectableAtOnce is the escape hatch: it does NOT declare anything healthy,
// it only pulls every backoff forward so the rotation may retry them now — and the tun probe judges.
func TestProbeNowMakesEveryBurnSelectableAtOnce(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, true, 0, "")
	p.now = func() int64 { return clk }
	nodeFail(p)
	if _, moved := p.rotateOnce(); moved {
		t.Fatal("setup: the burn should still be pending")
	}
	p.probeAllNow()
	p.mu.Lock()
	stillBurned := p.health["a"] != nil
	p.mu.Unlock()
	if !stillBurned {
		t.Fatal("probe now must not declare anything healthy — only the tun probe does that")
	}
	if _, moved := p.rotateOnce(); !moved || p.current() != "a" {
		t.Fatalf("probe now must make it selectable at once, got %q", p.current())
	}
}

// TestOneDestinationStillTakesTheVerdict covers the pool shape a client gets when the far node is down
// to a single IP: one destination, several sources. The single destination can never be burned or moved
// (failWith returns early below two entries) — but it is the tunnel's verdict MAILBOX, and without it
// pollPins never reads the file at all, so the node's asks are dropped and the source rotation walks
// blind. Here the fail must land on the SOURCE and the ok must clear it.
func TestOneDestinationStillTakesTheVerdict(t *testing.T) {
	dir := t.TempDir()
	clk := int64(1000)
	dst := NewPeerPool([]string{"d1"}, true, 0, filepath.Join(dir, "peerpool"))
	src := NewPeerPool([]string{"s1", "s2"}, true, 0, filepath.Join(dir, "srcpool"))
	dst.now = func() int64 { return clk }
	src.now = func() int64 { return clk }
	rc := newRotationController(dst, src)
	noop := func() {}
	rotDst := func(bool) { dst.fail() }
	rotSrc := func(bool) { src.fail() }

	writeFileAtomic(dst.cmdPath(), []byte(`{"cmd":"fail","key":"d1"}`), 0o644)
	rc.pollPins(noop, noop, rotDst, rotSrc, nil)

	dst.mu.Lock()
	dstBurned := dst.health["d1"] != nil
	dst.mu.Unlock()
	if dstBurned {
		t.Error("the only destination must never be condemned — there is nothing to move to")
	}
	src.mu.Lock()
	burned, cur := src.health["s1"] != nil, src.addrs[src.cur]
	src.mu.Unlock()
	if !burned {
		t.Fatal("the ask must reach the SOURCE: with one destination the source is the only axis left")
	}
	if cur != "s2" {
		t.Errorf("and it must move off the source it burned, got %q", cur)
	}

	writeFileAtomic(dst.cmdPath(), []byte(`{"cmd":"ok","key":"d1","src":"s1"}`), 0o644)
	rc.pollPins(noop, noop, rotDst, rotSrc, nil)
	src.mu.Lock()
	stillBurned := src.health["s1"] != nil
	src.mu.Unlock()
	if stillBurned {
		t.Error("an ok naming the source must clear it, even though the destination pool holds one entry")
	}
}

// TestNodeVerdictsDriveTheLiveDirectPool runs both verdicts through the file a real carrier polls, so
// the parse, the dispatch, the burn, the clear and the event are all the production path.
func TestNodeVerdictsDriveTheLiveDirectPool(t *testing.T) {
	cli, _, a1, _, _, _ := probePair(t, time.Second, "onej")
	p := cli.pp

	writeFileAtomic(p.cmdPath(), []byte(`{"cmd":"fail","key":"`+a1+`"}`), 0o644)
	deadline := time.Now().Add(15 * time.Second)
	for {
		p.mu.Lock()
		burned := p.health[a1] != nil
		p.mu.Unlock()
		if burned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node's fail command never burned %s", a1)
		}
		time.Sleep(50 * time.Millisecond)
	}

	writeFileAtomic(p.cmdPath(), []byte(`{"cmd":"ok","key":"`+a1+`"}`), 0o644)
	deadline = time.Now().Add(15 * time.Second)
	for {
		p.mu.Lock()
		burned := p.health[a1] != nil
		p.mu.Unlock()
		if !burned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node's OK never cleared the burn on %s", a1)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cli.st.mu.Lock()
	evs := append([]coreEvent(nil), cli.st.events...)
	cli.st.mu.Unlock()
	var healed bool
	for _, e := range evs {
		if e.Kind == "heal" && e.Code == "peer-retest" && e.Detail == a1 {
			healed = true
		}
	}
	if !healed {
		t.Fatalf("the OK must surface as one heal event naming %s, got %+v", a1, evs)
	}
	_ = filepath.Join
}
