package packet

import (
	"net"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func rawWithSession(t *testing.T) *Raw {
	t.Helper()
	s, err := crypto.NewSealer(crypto.CipherAES256, "a-psk-for-the-gate", true)
	if err != nil {
		t.Fatal(err)
	}
	r := &Raw{isClient: true, profile: "tcp", psk: "a-psk-for-the-gate", wake: make(chan struct{}, 1)}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 99, 0, 2)})
	r.session.Store(&sealerBox{s: s})
	return r
}

// usePort shuts the data gate (unanswered) so that a brand new four-tuple is opened by a handshake
// and not by a burst of queued tun traffic, and the ONLY thing that reopens it is the client branch
// of tryHandshake. The client loop decided whether to send that handshake from handshakeOutstanding
// alone -- session == nil || an ephemeral is in flight -- and a proactive rotation keeps the session
// and clears the ephemeral, so it asked for nothing and the gate stayed shut.
//
// freshTuple has three callers that leave the session alive and send no Init: rotatePeerRaw with
// proactive=true, rotateSourceRaw, and adoptSourceRaw. Every scheduled destination rotation, every
// scheduled source rotation and every manual source pin therefore stopped the tunnel carrying user
// traffic, while keepalives kept flowing and the dashboard kept showing it up.
//
// The gate is now itself a reason to knock, so any path that shuts it -- including one not written
// yet -- gets a handshake on the next turn of the loop, and freshTuple wakes the loop so that turn
// is immediate rather than one keepalive away.
func TestAShutFlowAsksToBeOpened(t *testing.T) {
	r := rawWithSession(t)
	if r.mustKnock() {
		t.Fatal("a settled session with an open gate must not be asking for a handshake")
	}

	for _, tc := range []struct {
		name string
		shut func(*Raw)
	}{
		{"a scheduled destination rotation", func(r *Raw) {
			r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 99, 0, 3)})
			r.freshTuple()
		}},
		{"a scheduled source rotation", func(r *Raw) {
			r.localIP.Store(&net.IPAddr{IP: net.IPv4(10, 99, 0, 9)})
			r.freshTuple()
		}},
		{"a manual source pin", func(r *Raw) { r.freshTuple() }},
		{"a redrawn source port", func(r *Raw) { r.usePort(8443) }},
	} {
		r := rawWithSession(t)
		tc.shut(r)
		if !r.unanswered.Load() {
			t.Fatalf("%s: setup — the gate is not shut, so this proves nothing", tc.name)
		}
		if !r.mustKnock() {
			t.Errorf("%s: the gate is shut and the loop is not asking for a handshake — every tun "+
				"packet is dropped and nothing will ever reopen it", tc.name)
		}
	}
}

// The loop only reads mustKnock when it runs, so a rotation driven from the pin-poll goroutine has to
// wake it; otherwise the tunnel stays dark for up to a keepalive interval even though the fix above
// would have opened it.
func TestADrawnTupleWakesTheLoop(t *testing.T) {
	r := rawWithSession(t)
	r.freshTuple()
	select {
	case <-r.wake:
	default:
		t.Fatal("freshTuple drew a new tuple and left the client loop asleep")
	}
}

// The server never draws, so it must never be gated: it has nothing to wait for and would simply stop
// carrying.
func TestAServerGateStaysOpen(t *testing.T) {
	r := &Raw{isClient: false, profile: "tcp"}
	r.learnClientPort(9443)
	if r.unanswered.Load() {
		t.Fatal("the server shut its own gate")
	}
}
