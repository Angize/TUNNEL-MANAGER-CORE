package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// liveTunnel is a pool plus the one thing the pool does not hold: where the carrier is REALLY sending.
// The datagram carriers move that only through a rotate, never by asking the pool anything — which is
// the whole reason a verdict may not be keyed on the pool's own selection.
type liveTunnel struct {
	p    *PeerPool
	rc   *rotationController
	live string   // the carrier's destination, moved only by rotDst
	burn []string // every endpoint the pool condemned, in order
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

// rotDst is the carrier's swap func: it advances the pool and follows it, exactly as rotatePeerUDP does.
func (lt *liveTunnel) rotDst(bool) {
	if addr, moved := lt.p.nextEndpoint(false); moved {
		lt.live = addr
	}
}

// nodeSees is what pool_failover reads to key its verdict: the ACTIVE field of the published status
// file. Read from disk, not from the struct, so the test cannot be kinder to the core than the node is.
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

// ladder snapshots how far down the health FSM each endpoint has been walked. Presence is not enough:
// an endpoint burned twice is condemned twice, and a test that only asks "is it burned" cannot see the
// second one at all.
func (lt *liveTunnel) ladder() map[string]int {
	lt.p.mu.Lock()
	defer lt.p.mu.Unlock()
	out := map[string]int{}
	for _, a := range lt.p.addrs {
		if r := lt.p.health.rec(a); r != nil {
			out[a] = r.fails + 1 // +1 so "tracked at step 0" outranks "never burned"
		}
	}
	return out
}

// verdict delivers one fail the way the node does — keyed on the published active endpoint — through
// the real judge, and records every endpoint the pool walked further down.
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

// TestAVerdictIsChargedToTheEndpointItNamed is the class, and it is not a race.
//
// The node keys every verdict on the endpoint the status file publishes. judge() used to ask the pool
// "which one is current?" and compare — but current() is a SELECTION: it re-picks by health and commits
// the cursor to what it picks, so asking moved the answer. On the datagram carriers, whose live
// destination follows only a rotate, the cursor then named an endpoint the tunnel was not on, the
// comparison failed, and the verdict took the "the rotation moved under us" path: it burned without
// leaving, so the tunnel stayed on the dead endpoint for that round. The round after, the status file
// published the drifted cursor, so the node keyed its next verdict on an endpoint nothing had measured
// and THAT one was condemned.
//
// The state is reached through selectEntry -> current() -> releasePin: a pin abandoned WITHOUT landing,
// which is the sequence restorePinTookLocked exists to serve — it puts back the burn the pin cleared, so
// the cursor is left on a condemned endpoint with no deliberate choice recorded.
//
// It asserts the two things the bug broke, not "exactly one burn": an entry still inside its backoff is
// deliberately not walked further, so counting steps would tie this to a rule it is not about.
func TestAVerdictIsChargedToTheEndpointItNamed(t *testing.T) {
	lt := newLiveTunnel(t, "a", "b")

	// One ordinary failover first, so something is burned and there is a selection to disagree about.
	lt.rotDst(false)
	if lt.live != "b" {
		t.Fatalf("setup: the carrier did not follow the pool, at %q", lt.live)
	}
	// The operator pins the burned endpoint back, the carrier adopts it, then the pin releases.
	lt.pinAndRelease(t, "a")
	if lt.live != "a" {
		t.Fatalf("setup: the pin did not land, carrier at %q", lt.live)
	}

	// The node measures the tunnel — which is on "a" — and says so.
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

// pinAndRelease is the operator's «این را فعال کن» in full: pin an endpoint, let the carrier adopt it
// the way the pin poller does, then let the pin go. It is the sequence that used to leave the pool's
// cursor free to be re-selected out from under the carrier.
func (lt *liveTunnel) pinAndRelease(t *testing.T, key string) {
	t.Helper()
	if !lt.p.selectEntry(key) {
		t.Fatalf("could not pin %s", key)
	}
	lt.live = lt.p.current() // adoptPeerUDP reads the pin and FOLLOWS it
	lt.p.releasePin()
}

// TestNoVerdictEverCondemnsAnEndpointTheTunnelWasNotOn is the same rule as an invariant rather than a
// single arrangement, because a cursor that drifts a little further each round is not something one
// case can catch. The operator keeps pinning while the probe keeps judging — which is exactly when this
// matters, since a pin is what an operator reaches for on a tunnel that is already misbehaving.
//
// Every verdict is keyed the way the node keys it: off the published status file, never off anything
// the test knows privately.
func TestNoVerdictEverCondemnsAnEndpointTheTunnelWasNotOn(t *testing.T) {
	lt := newLiveTunnel(t, "a", "b", "c")
	clk := int64(1000)
	lt.p.now = func() int64 { return clk }

	for round := 1; round <= 12; round++ {
		if round%3 == 0 {
			// Pin somewhere the carrier is NOT, so the jump is real.
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
		clk += 4 // the sweep interval; nothing here depends on a backoff elapsing
	}

	// And the cursor must still name the live destination, or the next round starts the drift again.
	lt.p.mu.Lock()
	cur := lt.p.addrs[lt.p.cur]
	lt.p.mu.Unlock()
	if cur != lt.live {
		t.Errorf("the pool's cursor names %s, the carrier is on %s", cur, lt.live)
	}
}
