package packet

import (
	"net"
	"testing"
)

func TestARawBuiltAnyOtherWayCarriesFromTheStart(t *testing.T) {
	r := &Raw{isClient: true, profile: "tcp"}
	if r.unanswered.Load() {
		t.Fatalf("the zero value must mean CARRYING -- dozens of tests build a Raw by literal, and " +
			"a gate that defaults to shut silences every one of them")
	}
}

func TestADrawnPortCarriesNothingUntilItIsAnswered(t *testing.T) {
	r := &Raw{isClient: true, profile: "tcp", sportRandom: true}
	r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(10, 99, 0, 2)})

	r.usePort(8443)
	if !r.unanswered.Load() {
		t.Errorf("the draw made a brand new four-tuple and left it carrying -- the queued tun " +
			"traffic then opens it with a burst of thousands instead of a handshake")
	}
	if r.ci.Load() != nil {
		t.Errorf("the draw kept the old ephemeral, so an answer meant for the port we LEFT would " +
			"open the port we are on")
	}

	r.unanswered.Store(false)
	r.freshTuple()
	if !r.unanswered.Load() {
		t.Errorf("freshTuple draws a port too, so it must shut the flow as well")
	}
}

func TestAServerNeverDrawsAndIsNeverShut(t *testing.T) {
	r := &Raw{isClient: false, profile: "tcp"}
	r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(10, 99, 0, 1)})

	r.learnClientPort(9443)
	if r.unanswered.Load() {
		t.Errorf("the server followed its peer to a new client port and shut its own flow -- it " +
			"draws nothing, so it has nothing to wait for and would stop carrying for good")
	}
	if r.cport() != 9443 {
		t.Errorf("the server did not follow the client port: %d", r.cport())
	}
}
