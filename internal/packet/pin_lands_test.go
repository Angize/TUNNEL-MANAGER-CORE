package packet

import (
	"testing"
	"time"
)

// TestManualPinReleasesOnLanding drives the panel's «make this active» through the file the core really
// polls, and asserts the pin lets go as soon as the carrier is up on the endpoint it aimed at. The
// release used to hang off healEvents, whose gate needs a prior failure to have been counted — which a
// jump that simply worked never produces — so a landed pin sat out the whole pinTTL with failover and
// the timed rotation frozen behind it.
func TestManualPinReleasesOnLanding(t *testing.T) {
	cli, _, _, a2, _, _ := probePair(t, time.Second, "pinl")
	writeFileAtomic(cli.pp.cmdPath(), []byte(`{"key":"`+a2+`"}`), 0o644)

	// The jump itself: the pool takes the key, the carrier re-points and re-handshakes there.
	deadline := time.Now().Add(15 * time.Second)
	for {
		p := cli.peer.Load()
		if p != nil && p.String() == a2 && cli.session.Load() != nil && cli.peerAnswered.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the manual jump never landed on %s", a2)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Landed. The pin must be gone at once — the whole point of a momentary jump.
	deadline = time.Now().Add(5 * time.Second)
	for cli.pp.isPinned() {
		if time.Now().After(deadline) {
			t.Fatal("the pin survived the landing — it now holds indefinitely, freezing failover and " +
				"rotation behind a jump that already succeeded")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
