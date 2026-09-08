//go:build linux

package packet

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// One pool for every carrier means one BEHAVIOUR for every carrier. This runs the same script against
// udp, raw, tcp and ws and asserts the same answers: what a walk burns, what a lap forgives, and every
// one of the four ways a burn is lifted.
//
// The two free rungs are deliberately left unarmed on every rig, so a fail verdict reaches the walk on
// the first beat. What is under test is the pool, not the ladder in front of it.

type poolRig struct {
	name              string
	lowKind, highKind string
	lowRotate         string
	low, high         *PeerPool
	st                *coreStatus
	rc                *rotationController
	poll              func()
}

func (r *poolRig) live() (string, string) { return r.rc.livePair() }

func (r *poolRig) deliver(t *testing.T, c poolCmd) {
	t.Helper()
	path := r.st.verdictPath()
	if c.Key != "" {
		path = r.st.selectPath()
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	r.poll()
}

func (r *poolRig) failNow(t *testing.T) {
	t.Helper()
	low, high := r.live()
	r.deliver(t, poolCmd{Cmd: cmdFail, Low: low, High: high, Epoch: r.st.pathEpoch()})
}

func (r *poolRig) status(t *testing.T) struct {
	Pair   pairStatus     `json:"pair"`
	Health []healthStatus `json:"health"`
	Events []coreEvent    `json:"events"`
} {
	t.Helper()
	var st struct {
		Pair   pairStatus     `json:"pair"`
		Health []healthStatus `json:"health"`
		Events []coreEvent    `json:"events"`
	}
	data, err := os.ReadFile(r.st.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// Every detail the carrier published under one kind/code, oldest first. A rotation event is written
// only when the walk actually moved the cursor, which makes it the one observable a mutating read
// cannot forge: current() steps off a burned entry on its own, and fail() publishes on its way out.
func (r *poolRig) eventDetails(t *testing.T, kind, code string) []string {
	t.Helper()
	var out []string
	for _, e := range r.status(t).Events {
		if e.Kind == kind && e.Code == code {
			out = append(out, e.Detail)
		}
	}
	return out
}

func (r *poolRig) sawEvent(t *testing.T, kind, code, detail string) bool {
	t.Helper()
	for _, e := range r.status(t).Events {
		if e.Kind == kind && e.Code == code && e.Detail == detail {
			return true
		}
	}
	return false
}

func burned(p *PeerPool, key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.health.healthy(key)
}

func eligible(p *PeerPool, key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health.eligible(key)
}

const rigPSK = "a-psk-for-the-cross-carrier-pool-probe"

var rigDsts = []string{"198.51.100.1:5555", "198.51.100.2:5555", "198.51.100.3:5555"}
var rigSrcs = []string{"127.0.0.1", "127.0.0.2"}

func udpRig(t *testing.T) *poolRig {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b := &UDP{isClient: true, cryptoOn: true, psk: rigPSK,
		wake: make(chan struct{}, 1), closeCh: make(chan struct{})}
	b.conn.Store(c)
	b.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	b.SetPeerPool(NewPeerPool(rigDsts, 0))
	b.SetSourcePool(NewPeerPool(rigSrcs, 0))
	b.soloPeer.Store(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5555})
	rc := b.newController()
	rc.port.setRoll(nil)
	rc.session.setDrop(nil)
	return &poolRig{name: "udp", lowKind: axisDst, highKind: axisSrc, lowRotate: "peer-rotate", low: b.pp, high: b.sp, st: b.st, rc: rc,
		poll: func() { rc.poll(b.rotatePeerUDP, b.rotateSourceUDP, b.selectedUDP, b.st.pathEpoch) }}
}

func rawRig(t *testing.T) *poolRig {
	t.Helper()
	r := &Raw{isClient: true, profile: "udp", psk: rigPSK,
		wake: make(chan struct{}, 1), closeCh: make(chan struct{})}
	r.SetStatusPath(filepath.Join(t.TempDir(), "core.status"))
	r.SetPeerPool(NewPeerPool(rigDsts, 0))
	r.SetSourcePool(NewPeerPool(rigSrcs, 0))
	rc := newRotationController(r.pp, r.sp)
	rc.attachStatus(r.st)
	r.st.setPair(rc.pairStatus)
	return &poolRig{name: "raw", lowKind: axisDst, highKind: axisSrc, lowRotate: "peer-rotate", low: r.pp, high: r.sp, st: r.st, rc: rc,
		poll: func() { rc.poll(r.rotatePeerRaw, r.rotateSourceRaw, r.selectedRaw, r.st.pathEpoch) }}
}

func tcpRig(t *testing.T) *poolRig {
	t.Helper()
	b, pp, sp := peerCarrier(t, rigDsts, rigSrcs)
	return &poolRig{name: "tcp", lowKind: axisDst, highKind: axisSrc, lowRotate: "peer-rotate", low: pp, high: sp, st: b.st, rc: &b.rc,
		poll: func() { b.rc.poll(b.rotateLowTCP, b.rotateHighTCP, b.selectedTCP, b.st.pathEpoch) }}
}

func wsRig(t *testing.T) *poolRig {
	t.Helper()
	b, pp, sp := edgeCarrier(t, rigDsts, snis("front-a", "front-b"))
	return &poolRig{name: "ws", lowKind: axisIP, highKind: axisSNI, lowRotate: "edge-rotate", low: pp, high: sp, st: b.st, rc: &b.rc,
		poll: func() { b.rc.poll(b.rotateLowTCP, b.rotateHighTCP, b.selectedTCP, b.st.pathEpoch) }}
}

var everyCarrier = []func(*testing.T) *poolRig{udpRig, rawRig, tcpRig, wsRig}

func eachCarrier(t *testing.T, f func(t *testing.T, r *poolRig)) {
	t.Helper()
	for _, mk := range everyCarrier {
		r := mk(t)
		t.Run(r.name, func(t *testing.T) { f(t, r) })
	}
}

// A walk condemns the entry the cursor names, tags the burn with that pool's own axis, and only then
// looks for somewhere to go.
func TestEveryCarrierBurnsWhatItWalksOffAndTagsItsAxis(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		was, _ := r.live()
		r.failNow(t)

		if !burned(r.low, was) {
			t.Fatalf("%s: the walk left %q healthy", r.name, was)
		}
		if !r.sawEvent(t, "burn", "tun-probe", r.lowKind+":"+was) {
			t.Fatalf("%s: no burn/%s:%s in the status file", r.name, r.lowKind, was)
		}
		// Not the cursor: current() steps off a burned entry by itself, and fail() publishes the status
		// on its way out, so the cursor has moved whether the walk moved it or not. The rotation event
		// is written only when the walk itself reported a move.
		moves := r.eventDetails(t, "down", r.lowRotate)
		if len(moves) == 0 {
			t.Fatalf("%s: the walk condemned %q and published no %s — it never went anywhere",
				r.name, was, r.lowRotate)
		}
		if last := moves[len(moves)-1]; last == "ip:"+was {
			t.Fatalf("%s: the walk reported moving to %q, the endpoint it had just condemned", r.name, was)
		}
		if _, high := r.live(); burned(r.high, high) {
			t.Fatalf("%s: the high axis was condemned on the first beat", r.name)
		}
	})
}

// A lap steps the high axis and forgives every entry on the low one: under a source or a domain it has
// not been tried on, a burned endpoint has earned a fresh trial.
func TestEveryCarrierForgivesTheLowAxisWhenTheHighOneSteps(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		firstHigh, _ := "", ""
		_, firstHigh = r.live()

		moved := false
		for i := 0; i < 4*len(rigDsts); i++ {
			r.failNow(t)
			if _, h := r.live(); h != firstHigh {
				moved = true
				break
			}
		}
		if !moved {
			t.Fatalf("%s: the high axis never stepped in %d verdicts", r.name, 4*len(rigDsts))
		}
		if !burned(r.high, firstHigh) {
			t.Fatalf("%s: the high axis stepped off %q without condemning it", r.name, firstHigh)
		}
		for _, d := range rigDsts {
			if burned(r.low, d) {
				t.Fatalf("%s: %q is still condemned after the high axis moved", r.name, d)
			}
		}
	})
}

// The node's ok is the only thing that clears a burn on evidence, and it says so on both axes.
func TestEveryCarrierLiftsABurnWhenTheProbeSaysItCarries(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		low, high := r.live()
		r.low.markSuspect(low, "test")
		r.high.markSuspect(high, "test")
		if !burned(r.low, low) || !burned(r.high, high) {
			t.Fatalf("%s: setup did not condemn the pair", r.name)
		}

		r.deliver(t, poolCmd{Cmd: cmdOK, Low: low, High: high, Epoch: r.st.pathEpoch()})

		if burned(r.low, low) {
			t.Fatalf("%s: %q is still condemned after the probe said it carries", r.name, low)
		}
		if burned(r.high, high) {
			t.Fatalf("%s: %q is still condemned after the probe said it carries", r.name, high)
		}
		if !r.sawEvent(t, "heal", "tun-probe", r.lowKind+":"+low) {
			t.Fatalf("%s: no heal/%s:%s reached the log", r.name, r.lowKind, low)
		}
		if !r.sawEvent(t, "heal", "tun-probe", r.highKind+":"+high) {
			t.Fatalf("%s: no heal/%s:%s reached the log", r.name, r.highKind, high)
		}
	})
}

// The operator can end one wait without touching the others.
func TestEveryCarrierLetsTheOperatorRetestOneEntry(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		other := rigDsts[len(rigDsts)-1]
		low, _ := r.live()
		r.low.markSuspect(low, "test")
		r.low.markSuspect(other, "test")
		if eligible(r.low, low) || eligible(r.low, other) {
			t.Fatalf("%s: setup left an entry eligible", r.name)
		}

		r.deliver(t, poolCmd{Cmd: cmdRetest, Kind: r.lowKind, Key: low})

		if !eligible(r.low, low) {
			t.Fatalf("%s: %q is still waiting after the operator asked for a retest", r.name, low)
		}
		if eligible(r.low, other) {
			t.Fatalf("%s: retesting %q also ended the wait on %q", r.name, low, other)
		}
	})
}

// And an operator pick clears that entry outright and takes the cursor there.
func TestEveryCarrierLetsTheOperatorPickABurnedEntry(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		want := rigDsts[len(rigDsts)-1]
		r.low.markSuspect(want, "test")

		r.deliver(t, poolCmd{Kind: r.lowKind, Key: want})

		if burned(r.low, want) {
			t.Fatalf("%s: %q is still condemned after the operator picked it", r.name, want)
		}
		if now, _ := r.live(); now != want {
			t.Fatalf("%s: the operator picked %q and the pool is on %q", r.name, want, now)
		}
	})
}

// The last way out needs nobody: the entry's own backoff runs down on the pool's clock.
func TestEveryCarrierLetsABurnExpireOnItsOwnClock(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		clk := int64(1000)
		r.low.now = func() int64 { return clk }
		low, _ := r.live()

		r.low.markSuspect(low, "test")
		if eligible(r.low, low) {
			t.Fatalf("%s: a fresh burn is eligible straight away", r.name)
		}
		clk += suspectBackoff[0] - 1
		if eligible(r.low, low) {
			t.Fatalf("%s: %q came back one second early", r.name, low)
		}
		clk += 2
		if !eligible(r.low, low) {
			t.Fatalf("%s: %q never came back after its backoff ran down", r.name, low)
		}
	})
}

// And the file the node reads names both axes, so a burn can be told from the axis it happened on.
func TestEveryCarrierNamesBothAxesInTheStatusFile(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		r.failNow(t)
		st := r.status(t)

		if st.Pair.LowKind != r.lowKind || st.Pair.HighKind != r.highKind {
			t.Fatalf("%s: the pair reports kinds %q/%q, want %q/%q",
				r.name, st.Pair.LowKind, st.Pair.HighKind, r.lowKind, r.highKind)
		}
		seen := map[string]int{}
		for _, h := range st.Health {
			seen[h.Kind]++
		}
		if seen[r.lowKind] != len(rigDsts) {
			t.Fatalf("%s: %d health rows tagged %q, want %d", r.name, seen[r.lowKind], r.lowKind, len(rigDsts))
		}
		if seen[r.highKind] == 0 {
			t.Fatalf("%s: the high axis has no health rows at all", r.name)
		}
	})
}
