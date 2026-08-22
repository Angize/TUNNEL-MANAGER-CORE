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

// And once it does come back, the line names the port it came back on -- not the one it left.
func TestTheLineNamesThePortItRecoveredOn(t *testing.T) {
	r, path := rollingPort(t)

	r.rollSourcePort()
	r.rollSourcePort()
	came := r.cport()
	r.st.reconnected("raw", came)

	ev := coreStatusEvents(t, path)
	if len(ev) != 1 || ev[0].Code != "port-roll" {
		t.Fatalf("after recovery: %+v, want exactly one port-roll", ev)
	}
	if want := "sport:" + strconv.Itoa(int(came)); ev[0].Detail != want {
		t.Fatalf("the line says %q, want %q -- the operator needs the port that WORKS", ev[0].Detail, want)
	}
	if came == 40000 {
		t.Fatal("setup: the draws never moved the port, so this proves nothing")
	}
}
