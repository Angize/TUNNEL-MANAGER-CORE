package packet

import (
	"net"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func rollingPort(t *testing.T) (*Raw, string) {
	t.Helper()
	r := &Raw{isClient: true, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.cliPort.Store(40000)
	r.link = &capturingLink{r: r}
	path := filepath.Join(t.TempDir(), "core.status")
	r.SetStatusPath(path)
	// The one line Run() adds: the live path, which is where the port the tunnel is actually on lives.
	r.st.trackPath(r.livePath, r.closeCh)
	t.Cleanup(func() { close(r.closeCh) })
	return r, path
}

func greenSession(t *testing.T, r *Raw) {
	t.Helper()
	sl, err := crypto.NewSealer(crypto.CipherChaCha, "port-refresh-psk-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	r.session.Store(&sealerBox{s: sl})
	if r.link == nil {
		r.link = &capturingLink{r: r}
	}
}

// The draw itself says nothing, however many times the ladder spends it. What the operator needs is
// the port the tunnel CAME BACK on, and until it comes back there is no such port -- so an outage that
// never recovers writes no port line at all. Driven through the real rung: rollSourcePort is what the
// ladder calls.
//
// This covers the silent half end to end. The other half -- one line naming the port, once the carrier
// reports it is up -- is coreStatus's rule and is tested there, in TestAPortRedrawIsOnlyNewsIfItWorked.
func TestDrawsAloneWriteNothing(t *testing.T) {
	r, path := rollingPort(t)

	for i := 0; i < 5; i++ {
		if !r.rollSourcePort() {
			t.Fatalf("draw %d did not move the port", i+1)
		}
	}
	if ev := coreStatusEvents(t, path); len(ev) != 0 {
		t.Fatalf("five draws in an outage that never recovered wrote %d event(s): %+v. The ladder "+
			"redraws every few seconds; a line each is the spam that buries the burn that follows", len(ev), ev)
	}
}

// And once the PROBE says traffic is crossing, the line names the port it is crossing on -- not the
// one it left, and not one the carrier merely got a handshake answer on.
func TestTheLineNamesThePortItRecoveredOn(t *testing.T) {
	r, path := rollingPort(t)
	greenSession(t, r)

	r.rollSourcePort()
	r.rollSourcePort()
	came := r.cport()
	r.st.carrying()

	ev := coreStatusEvents(t, path)
	if len(ev) != 1 || ev[0].Code != "port-roll" {
		t.Fatalf("after recovery: %+v, want exactly one port-roll", ev)
	}
	// Two draws were spent, so the line has to say two: "it came back" alone does not tell the
	// operator whether the budget was nearly gone.
	if want := "sport:" + strconv.Itoa(int(came)) + " tries:2"; ev[0].Detail != want {
		t.Fatalf("the line says %q, want %q -- the operator needs the port that WORKS and what it cost",
			ev[0].Detail, want)
	}
	if came == 40000 {
		t.Fatal("setup: the draws never moved the port, so this proves nothing")
	}
}

// The carrier's own reconnect must never write that line. A source-port draw SENDS A HANDSHAKE, and an
// answered handshake is exactly what a filtered path still gives -- so wiring the line here announced
// every draw as a success while the ladder climbed straight past it. Two "came back with this port"
// lines two seconds apart, then a re-handshake, then a burn, then the walk that actually fixed it.
func TestTheCarriersOwnReconnectNeverClaimsThePort(t *testing.T) {
	r, path := rollingPort(t)
	greenSession(t, r)

	r.rollSourcePort()
	r.st.reconnected("raw") // the handshake was answered: true, and says nothing about carrying
	r.rollSourcePort()
	r.st.reconnected("raw")

	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "port-roll" {
			t.Fatalf("a handshake answer announced the port as working: %+v", e)
		}
	}
	r.st.carrying()
	n := 0
	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "port-roll" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the probe found traffic crossing and got %d port lines, want exactly 1", n)
	}
}

// ...and through the real ladder: once it has spent both draws and moved on to the handshake rung, the
// recovery that follows is not the port's doing and must not be credited to it.
func TestAPortLineDiesWhenTheLadderClimbsPastIt(t *testing.T) {
	r, path := rollingPort(t)
	greenSession(t, r)

	// The three lines Raw.clientLoop wires.
	rc := newRotationController(nil, nil)
	rc.session.setDrop(func() bool { return true })
	rc.port.setRoll(r.rollSourcePort)
	rc.attachStatus(r.st)

	epoch := r.st.pathEpoch()
	for i := 0; i <= portTries; i++ { // portTries draws, then one verdict past them
		liveVerdict(t, rc.verdict, epoch, poolCmd{Cmd: cmdFail})
		rc.poll(func(bool) {}, func(bool) {}, nil, r.st.pathEpoch)
	}
	liveVerdict(t, rc.verdict, r.st.pathEpoch(), poolCmd{Cmd: cmdOK})
	rc.poll(func(bool) {}, func(bool) {}, nil, r.st.pathEpoch)

	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "port-roll" {
			t.Fatalf("the ladder had already moved past the source port, and the recovery was still "+
				"credited to it: %+v", e)
		}
	}
}
