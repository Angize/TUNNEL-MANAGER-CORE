package packet

import (
	"testing"
	"time"
)

type liveTunnel struct {
	b    *TCP
	p    *PeerPool
	rc   *rotationController
	live string
	burn []string
	now  time.Time
}

func newLiveTunnel(t *testing.T, addrs ...string) *liveTunnel {
	t.Helper()
	b, p, _ := peerCarrier(t, addrs, nil)
	lt := &liveTunnel{b: b, p: p, rc: &b.rc, now: time.Now()}
	lt.live = addrs[0]
	lt.b.pretendConnected(lt.live, "")
	return lt
}

func (lt *liveTunnel) rotDst(bool) {
	if addr, moved := lt.p.nextEndpoint(false); moved {
		lt.live = addr
		lt.b.pretendConnected(addr, "")
	}
}

// The endpoint the node would key its verdict on: the machine-readable pair in the one status file.
func (lt *liveTunnel) nodeSees(t *testing.T) string {
	t.Helper()
	return lt.b.readStatus(t).Pair.Low
}

func (lt *liveTunnel) ladder() map[string]int {
	lt.p.mu.Lock()
	defer lt.p.mu.Unlock()
	out := map[string]int{}
	for _, a := range lt.p.addrs {
		if r := lt.p.health.rec(a); r != nil {
			out[a] = int(r.nextRetest)
		}
	}
	return out
}

func (lt *liveTunnel) verdict(t *testing.T) (key string) {
	t.Helper()
	key = lt.nodeSees(t)
	before := lt.ladder()
	lt.rc.judge(poolCmd{Cmd: cmdFail, Low: key, Epoch: lt.b.st.pathEpoch()}, lt.rotDst, func(bool) {}, lt.b.st.pathEpoch())
	for a, n := range lt.ladder() {
		if n != before[a] {
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
	lt.b.pretendConnected(lt.live, "")
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

			if key = lt.verdict(t); key != was {
				t.Fatalf("round %d: the second verdict keyed on %s while the carrier was on %s",
					round, key, was)
			}
			for _, b := range lt.burn[n:] {
				if b != was {
					t.Fatalf("round %d: condemned %s, but the probe measured %s", round, b, was)
				}
			}
		}
		if lt.live == was {
			t.Fatalf("round %d: two verdicts on %s and the tunnel is still there — the experiment "+
				"never moves, so the next sweep measures the same dead path", round, was)
		}
		clk += deadRetest
	}

	lt.p.mu.Lock()
	cur := lt.p.addrs[lt.p.cur]
	lt.p.mu.Unlock()
	if cur != lt.live {
		t.Errorf("the pool's cursor names %s, the carrier is on %s", cur, lt.live)
	}
}
