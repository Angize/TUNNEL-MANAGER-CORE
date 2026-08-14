//go:build linux

package packet

import (
	"net"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

const liveProbePSK = "tVYafNLrHaId1AaEM80YebyPzXThOEr2adA27E6mbRc="

// liveClient is a raw CLIENT holding an established session, with a probe already outstanding -- the
// state the decision under test is made in.
func liveClient(t *testing.T) (*Raw, *crypto.Ephemeral) {
	t.Helper()
	s, err := crypto.NewSealer("chacha20-poly1305", liveProbePSK, true)
	if err != nil {
		t.Fatal(err)
	}
	r := &Raw{isClient: true, psk: liveProbePSK, cipher: "chacha20-poly1305",
		keepalive: 5 * time.Second, closeCh: make(chan struct{})}
	r.session.Store(&sealerBox{s: s})
	ci := ephemeral(t)
	r.ci.Store(ci)
	r.probed.Store(true)
	return r, ci
}

// respFor is what the peer sends back to an init -- built by the crypto package, not hand-rolled, so
// the client's own ParseResp is really exercised.
func respFor(t *testing.T, clientPub [32]byte) []byte {
	t.Helper()
	return crypto.RespMsg(liveProbePSK, clientPub, ephemeral(t))
}

// A datagram client cannot tell a restarted peer from a broken path: both are silence. So the dead
// window has to be long enough to be SURE, because the reaction to it is destructive -- throw the
// session away. The liveness probe splits the two apart with a handshake the peer either answers or
// does not, and the tests here pin the three properties that makes it safe:
//
//  1. the probe fires strictly INSIDE the dead window, and never so early that one lost ping trips it;
//  2. a peer that answers the probe while the session is ALSO being answered changes nothing -- the
//     new keys are dropped, because re-keying a working tunnel on every probe is worse than the bug;
//  3. a peer that answers the probe while the session has gone unanswered is a peer that restarted,
//     and the client moves at once instead of waiting out the rest of the dead window.

func TestProbeWindowSitsInsideTheDeadWindow(t *testing.T) {
	old := deadMult
	defer func() { deadMult = old }()

	for _, tc := range []struct {
		name string
		mult int64
		ka   time.Duration
	}{
		{"the tightest setting the clamp allows", 2, 5 * time.Second},
		{"the default", 3, 5 * time.Second},
		{"the recommended longer window", 5, 10 * time.Second},
		{"a very long window", 100, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deadMult = tc.mult
			dw, pw := deadWindow(tc.ka), probeWindow(tc.ka)
			if pw >= dw {
				t.Fatalf("probe window %v is not inside the dead window %v -- it would never fire", pw, dw)
			}
			if pw <= 0 {
				t.Fatalf("probe window %v must be positive", pw)
			}
			// One lost ping must not trip it. A keepalive tick is jittered up to 1.34x, so two
			// keepalives is the shortest gap that a single miss can produce.
			if floor := 2 * tc.ka; pw < floor && floor < dw {
				t.Fatalf("probe window %v is under the two-keepalive floor %v (dead window %v): "+
					"one lost ping would probe", pw, floor, dw)
			}
		})
	}
}

// The window is only worth having if it actually buys time. At the settings this fleet runs, the probe
// has to fire early enough that the answer is back well before the dead window would have fired.
func TestProbeWindowBuysTimeAtTheSettingsInUse(t *testing.T) {
	old := deadMult
	defer func() { deadMult = old }()

	deadMult = 3
	if dw, pw := deadWindow(5*time.Second), probeWindow(5*time.Second); dw-pw < 4*time.Second {
		t.Fatalf("keepalive=5 dead_mult=3: probe at %v vs dead at %v saves only %v", pw, dw, dw-pw)
	}
	deadMult = 5
	if dw, pw := deadWindow(10*time.Second), probeWindow(10*time.Second); dw-pw < 20*time.Second {
		t.Fatalf("keepalive=10 dead_mult=5: probe at %v vs dead at %v saves only %v", pw, dw, dw-pw)
	}
}

// staleSince is what both windows are read through; a client whose clock was never seeded must not
// read as stale, or a fresh tunnel probes before it has said hello.
func TestAnUnseededClockIsNotStale(t *testing.T) {
	if staleSince(0, time.Nanosecond) {
		t.Fatal("lastRx==0 read as stale: a fresh client would probe before its first frame")
	}
}

// markRx is the one place the silent spell ends, so it is the one place the probe flag may clear.
// If it did not, a tunnel that recovered would never probe again for the rest of its life.
func TestAnAnsweringSessionRearmsTheProbe(t *testing.T) {
	r := &Raw{}
	r.probed.Store(true)
	r.markRx()
	if r.probed.Load() {
		t.Error("raw: an inbound frame left the probe flag set -- this silent spell never ends")
	}
	if r.lastRx.Load() == 0 {
		t.Error("raw: markRx did not stamp the clock")
	}

	b := &UDP{}
	b.probed.Store(true)
	b.markRx()
	if b.probed.Load() {
		t.Error("udp: an inbound frame left the probe flag set -- this silent spell never ends")
	}

	f := &Flux{}
	f.probed.Store(true)
	f.markRx()
	if f.probed.Load() {
		t.Error("flux: an inbound frame left the probe flag set -- this silent spell never ends")
	}
}

// THE decision. A RESP is not self-evidently a handshake any more -- it may be the answer to a probe
// sent while the session was still live -- so what it means depends on whether the SESSION is being
// answered too. Getting this wrong in the safe-looking direction (always adopt, as the code did before
// the probe existed) silently re-keys a working tunnel on every probe.
func TestAProbeAnsweredByALiveSessionChangesNothing(t *testing.T) {
	r, ci := liveClient(t)
	before := r.sealer()
	r.lastRx.Store(time.Now().UnixNano()) // the session IS being answered: this was a false alarm

	r.tryHandshake(respFor(t, ci.Pub), &net.IPAddr{IP: testSrc}, 0)

	if r.sealer() != before {
		t.Fatal("a working tunnel was re-keyed by the answer to its own liveness probe")
	}
	if r.ci.Load() != nil {
		t.Error("the probe's ephemeral was left behind: the next stray frame re-parses against it")
	}
}

func TestAProbeAnsweredWhileTheSessionIsSilentMovesAtOnce(t *testing.T) {
	r, ci := liveClient(t)
	before := r.sealer()
	// Silent past the probe window but NOT past the dead one -- the whole span this exists for. The
	// peer is plainly up (it is answering right now) and is not holding our keys: it restarted.
	silence := (r.probeWin() + r.deadWin()) / 2
	if silence >= r.deadWin() {
		t.Fatalf("bad fixture: %v is not inside the dead window %v", silence, r.deadWin())
	}
	r.lastRx.Store(time.Now().Add(-silence).UnixNano())

	r.tryHandshake(respFor(t, ci.Pub), &net.IPAddr{IP: testSrc}, 0)

	if r.sealer() == before {
		t.Fatal("stayed on a session the peer does not hold, with the rest of the dead window still to wait")
	}
	if r.sealer() == nil {
		t.Fatal("dropped the session without installing the new one")
	}
	if r.ci.Load() != nil {
		t.Error("the ephemeral was not cleared, so a replayed resp can re-parse and wipe the fresh replay window")
	}
	if staleSince(r.lastRx.Load(), time.Second) {
		t.Error("the clock still reads the DEAD session's silence, so the fresh one starts already stale")
	}
	if r.probed.Load() {
		t.Error("the probe flag survived the move: the new session's first silent spell cannot probe")
	}
}

// The ordinary connect must still work. There is no session yet, so there is nothing to protect and
// nothing to decide -- adopt, exactly as before the probe existed.
func TestTheOrdinaryHandshakeStillAdopts(t *testing.T) {
	r, ci := liveClient(t)
	r.session.Store(nil) // no session: a first connect, or a re-handshake after the dead window
	r.lastRx.Store(time.Now().UnixNano())

	r.tryHandshake(respFor(t, ci.Pub), &net.IPAddr{IP: testSrc}, 0)

	if r.sealer() == nil {
		t.Fatal("a plain handshake no longer installs a session -- the probe broke the connect path")
	}
}

// One silence earns one probe. The flag is taken with Swap, so a client that stays silent for minutes
// sends a single init rather than one per keepalive -- which would pile candidate sessions onto the
// peer, and every frame that misses the live session is trial-opened against every one of them.
func TestOneSilentSpellSendsOneProbe(t *testing.T) {
	r := &Raw{}
	sent := 0
	for i := 0; i < 20; i++ {
		if !r.probed.Swap(true) {
			sent++
		}
	}
	if sent != 1 {
		t.Fatalf("a single silent spell sent %d probes, want 1", sent)
	}
	r.markRx() // the peer answered: the next spell is a new question
	if r.probed.Swap(true) {
		t.Fatal("after an answered frame the next silent spell could not probe")
	}
}
