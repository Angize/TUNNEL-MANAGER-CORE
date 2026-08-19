package packet

import (
	"testing"
	"time"
)

func TestManualPinReleasesOnLanding(t *testing.T) {
	cli, _, _, a2, _, _ := probePair(t, "pinl")
	writeFileAtomic(cli.pp.cmdPath(), []byte(`{"key":"`+a2+`"}`), 0o644)

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

	deadline = time.Now().Add(5 * time.Second)
	for cli.pp.isPinned() {
		if time.Now().After(deadline) {
			t.Fatal("the pin survived the landing — it now holds indefinitely, freezing failover and " +
				"rotation behind a jump that already succeeded")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
