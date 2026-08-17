package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// nodeCmd writes one command file exactly as the node does, then runs the poll that reads it. It goes
// through pollPins on purpose: the mis-target this file is about lives in that switch, not in any pool
// method, so a test that called the pool directly would pass while the wire stayed broken.
func nodeCmd(t *testing.T, rc *rotationController, c poolCmd) (rotated []string) {
	t.Helper()
	c.Epoch = testPathEpoch // these commands are all CURRENT; the staleness guard has its own test
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rc.dst.cmdPath(), data, 0o644); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
	rotDst := func(bool) {
		rc.dst.fail()
		rotated = append(rotated, "dst")
	}
	rotSrc := func(bool) {
		if rc.src != nil {
			rc.src.fail()
		}
		rotated = append(rotated, "src")
	}
	rc.pollPins(func() {}, func() {}, rotDst, rotSrc, nil, atPathEpoch)
	return rotated
}

// testPathEpoch is the path every command in these tests is stamped with, and the epoch pollPins is
// told the carrier is on — so each one reads as a verdict about the LIVE path.
const testPathEpoch = 7

// atPathEpoch is that epoch as pollPins takes it.
func atPathEpoch() int64 { return testPathEpoch }

func burnedIn(p *PeerPool) map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]bool{}
	for a, r := range p.health.recs {
		if r != nil {
			out[a] = true
		}
	}
	return out
}

// TestAStaleFailBurnsWhatItMeasured is the whole class. Between the node measuring and this core
// reading the command, the pool's OWN proactive timer can move: the node's probe takes up to a second
// and the poller that reads the file is a one-second ticker. Every rotate beat is therefore a window in
// which an unkeyed verdict condemns the endpoint the rotation just arrived at — a healthy one — and the
// advance that follows drops the tunnel straight back onto the endpoint that was actually measured.
func TestAStaleFailBurnsWhatItMeasured(t *testing.T) {
	dir := t.TempDir()
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)

	measured := p.current() // "a" — where the node's probe found nothing crossing
	if _, moved := p.rotateOnce(); !moved || p.current() != "b" {
		t.Fatalf("setup: the proactive beat did not move the pool, at %q", p.current())
	}
	rotated := nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: measured})

	burned := burnedIn(p)
	if !burned[measured] {
		t.Fatalf("the endpoint the probe measured (%s) was not burned; burned=%v", measured, burned)
	}
	if burned["b"] {
		t.Fatal("b was burned by a verdict measured on a — the tun probe never tested b")
	}
	if p.current() != "b" {
		t.Fatalf("a stale verdict moved the pool back onto %q; the rotation had already advanced", p.current())
	}
	if len(rotated) != 0 {
		t.Fatalf("a stale verdict must not drive a rotation, got %v", rotated)
	}
}

// TestAFreshFailStillBurnsAndAdvances pins the ordinary path down so keying does not quietly turn the
// failover off: when the key still names the active endpoint, it burns and advances exactly as before.
func TestAFreshFailStillBurnsAndAdvances(t *testing.T) {
	dir := t.TempDir()
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)

	measured := p.current()
	rotated := nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: measured})

	if !burnedIn(p)[measured] {
		t.Fatalf("%s was named and active, and was not burned", measured)
	}
	if p.current() == measured {
		t.Fatalf("the pool stayed on the endpoint it just burned (%s)", measured)
	}
	if len(rotated) != 1 || rotated[0] != "dst" {
		t.Fatalf("expected exactly one destination rotation, got %v", rotated)
	}
}

// TestAStaleFailNamingNothingWeHoldChangesNothing covers the key that no longer matches any entry —
// the pool was rebuilt under the verdict. Burning "the current one instead" would be the same
// mis-target with an extra step.
func TestAStaleFailNamingNothingWeHoldChangesNothing(t *testing.T) {
	dir := t.TempDir()
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)

	rotated := nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: "c"})

	if b := burnedIn(p); len(b) != 0 {
		t.Fatalf("a verdict about an endpoint we do not hold burned %v", b)
	}
	if p.current() != "a" || len(rotated) != 0 {
		t.Fatalf("it must not move the tunnel either, at %q rotated=%v", p.current(), rotated)
	}
}

// TestAFailThatNamesNothingCondemnsNothing covers the empty key. There is no "burn whatever is active
// instead" any more: that IS the mis-target, and a verdict with no endpoint in it is not a verdict.
func TestAFailThatNamesNothingCondemnsNothing(t *testing.T) {
	dir := t.TempDir()
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)

	rotated := nodeCmd(t, rc, poolCmd{Cmd: cmdFail})

	if b := burnedIn(p); len(b) != 0 {
		t.Fatalf("a verdict naming no endpoint burned %v", b)
	}
	if p.current() != "a" || len(rotated) != 0 {
		t.Fatalf("and it must not move the tunnel, at %q rotated=%v", p.current(), rotated)
	}
}

// TestAFailIsNeverReadAsAPin guards the dispatch itself. The pin arm keys off the SAME field, so a fail
// the burn arm does not consume — a key the rotation has already moved off, or one the pool does not
// hold at all — must not fall through to it and select the endpoint the probe just condemned.
func TestAFailIsNeverReadAsAPin(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"an endpoint the rotation moved off", "a"},
		{"an endpoint we do not hold", "zzz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
			rc := newRotationController(p, nil)
			if _, moved := p.rotateOnce(); !moved {
				t.Fatal("setup: the proactive beat did not move the pool")
			}
			nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: tc.key})
			if p.isPinned() {
				t.Fatalf("a fail verdict pinned %q", p.current())
			}
			if p.current() != "b" {
				t.Fatalf("a fail verdict that burns nothing moved the pool to %q", p.current())
			}
		})
	}
}

// TestTCPStaleFailBurnsWhatItMeasured is the same class on the tcp carrier, which polls the command
// file in its own loop rather than through pollPins — so the datagram fix says nothing about it.
func TestTCPStaleFailBurnsWhatItMeasured(t *testing.T) {
	dir := t.TempDir()
	st := newCoreStatus(filepath.Join(dir, "core.json"), "tcp · lab")
	p := NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0, filepath.Join(dir, "pool.json"))
	b := &TCP{pp: p, st: st, isClient: true, closeCh: make(chan struct{})}
	defer close(b.closeCh)

	measured := p.current()
	if _, moved := p.rotateOnce(); !moved {
		t.Fatal("setup: the proactive beat did not move the pool")
	}
	moved := p.current()
	if err := os.WriteFile(p.cmdPath(), []byte(`{"cmd":"fail","key":"`+measured+`"}`), 0o644); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
	go b.peerPinPollLoop()

	deadline := time.Now().Add(10 * time.Second)
	for !burnedIn(p)[measured] {
		if time.Now().After(deadline) {
			t.Fatalf("the endpoint the probe measured (%s) was never burned; burned=%v", measured, burnedIn(p))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if burnedIn(p)[moved] {
		t.Fatalf("%s was burned by a verdict measured on %s", moved, measured)
	}
	if p.current() != moved {
		t.Fatalf("a stale verdict moved the pool back to %q", p.current())
	}
	var burn coreEvent
	st.mu.Lock()
	for _, e := range st.events {
		if e.Kind == "burn" && e.Code == "tun-probe" {
			burn = e
		}
	}
	st.mu.Unlock()
	if burn.Detail != "ip:"+measured {
		t.Fatalf("the burn event names %s, but the probe condemned %s", burn.Detail, measured)
	}
}

// TestAKeyedOKStillClearsOnlyWhatItNames is the mirror half, driven through the same file path: the
// two verdicts have to agree about what a key means or one of them is condemning blind.
func TestAKeyedOKStillClearsOnlyWhatItNames(t *testing.T) {
	dir := t.TempDir()
	p := NewPeerPool([]string{"a", "b"}, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)

	nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: "a"}) // burns a, pool advances to b
	if !burnedIn(p)["a"] {
		t.Fatal("setup: a was not burned")
	}
	nodeCmd(t, rc, poolCmd{Cmd: cmdOK, Key: "b"})
	if !burnedIn(p)["a"] {
		t.Fatal("an OK naming b cleared a")
	}
	nodeCmd(t, rc, poolCmd{Cmd: cmdOK, Key: "a"})
	if burnedIn(p)["a"] {
		t.Fatal("an OK naming a did not clear a")
	}
}
