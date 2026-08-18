package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type liveTunnel struct {
	p    *PeerPool
	rc   *rotationController
	live string
	burn []string
}

func newLiveTunnel(t *testing.T, addrs ...string) *liveTunnel {
	t.Helper()
	dir := t.TempDir()
	lt := &liveTunnel{p: NewPeerPool(addrs, 0, filepath.Join(dir, "pool.json"))}
	lt.rc = newRotationController(lt.p, nil)
	lt.rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	lt.live = addrs[0]
	lt.p.writeStatus()
	return lt
}

func (lt *liveTunnel) rotDst(bool) {
	if addr, moved := lt.p.nextEndpoint(false); moved {
		lt.live = addr
	}
}

func (lt *liveTunnel) nodeSees(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(lt.p.statusPath)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var st peerPoolStatus
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return st.Active
}

func (lt *liveTunnel) ladder() map[string]int {
	lt.p.mu.Lock()
	defer lt.p.mu.Unlock()
	out := map[string]int{}
	for _, a := range lt.p.addrs {
		if r := lt.p.health.rec(a); r != nil {
			out[a] = r.fails + 1
		}
	}
	return out
}

func (lt *liveTunnel) verdict(t *testing.T) (key string) {
	t.Helper()
	key = lt.nodeSees(t)
	before := lt.ladder()
	lt.rc.judge(poolCmd{Cmd: cmdFail, Key: key, Epoch: testPathEpoch}, lt.rotDst, func(bool) {}, nil, testPathEpoch)
	for a, n := range lt.ladder() {
		if n > before[a] {
			lt.burn = append(lt.burn, a)
		}
	}
	return key
}

func TestAVerdictIsChargedToTheEndpointItNamed(t *testing.T) {
	lt := newLiveTunnel(t, "a", "b")

	lt.rotDst(false)
	if lt.live != "b" {
		t.Fatalf("setup: the carrier did not follow the pool, at %q", lt.live)
	}

	lt.pinAndRelease(t, "a")
	if lt.live != "a" {
		t.Fatalf("setup: the pin did not land, carrier at %q", lt.live)
	}

	if saw := lt.nodeSees(t); saw != "a" {
		t.Fatalf("setup: the node must see the endpoint the carrier is on, it sees %q", saw)
	}
	key := lt.verdict(t)

	for _, b := range lt.burn {
		if b != key {
			t.Errorf("the verdict named %s but %s was walked down — a burn may only ever fall on what "+
				"the probe measured", key, b)
		}
	}
	if lt.live == key {
		t.Errorf("the tunnel is still on %s, the endpoint just condemned: the verdict burned it without "+
			"leaving it, so the next round measures the same dead path again", key)
	}
}

func (lt *liveTunnel) pinAndRelease(t *testing.T, key string) {
	t.Helper()
	if !lt.p.selectEntry(key) {
		t.Fatalf("could not pin %s", key)
	}
	lt.live = lt.p.current()
	lt.p.releasePin()
}

func TestNoVerdictEverCondemnsAnEndpointTheTunnelWasNotOn(t *testing.T) {
	lt := newLiveTunnel(t, "a", "b", "c")
	clk := int64(1000)
	lt.p.now = func() int64 { return clk }

	for round := 1; round <= 12; round++ {
		if round%3 == 0 {

			for _, k := range lt.p.all() {
				if k != lt.live {
					lt.pinAndRelease(t, k)
					break
				}
			}
		}
		was := lt.live
		n := len(lt.burn)
		key := lt.verdict(t)
		if key != was {
			t.Fatalf("round %d: the node keyed its verdict on %s while the carrier was on %s — the "+
				"published active endpoint has drifted off the live one", round, key, was)
		}
		for _, b := range lt.burn[n:] {
			if b != was {
				t.Fatalf("round %d: condemned %s, but the probe measured %s", round, b, was)
			}
		}
		if lt.live == was {
			t.Fatalf("round %d: the verdict on %s left the tunnel on it — the experiment never moves, "+
				"so the next sweep measures the same dead path", round, was)
		}
		clk += 4
	}

	lt.p.mu.Lock()
	cur := lt.p.addrs[lt.p.cur]
	lt.p.mu.Unlock()
	if cur != lt.live {
		t.Errorf("the pool's cursor names %s, the carrier is on %s", cur, lt.live)
	}
}
