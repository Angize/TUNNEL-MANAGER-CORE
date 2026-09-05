package packet

import (
	"testing"
	"time"
)

// While the carrier is DOWN the published pair is the cursor, so it follows a jump at once. A verdict
// arriving in that window must name the edge the tunnel is attempting, not the one it just left.
func TestThePublishedPairFollowsAJumpWhileDown(t *testing.T) {
	b, p := edgeCarrier(t, []string{"e1", "e2"}, snis("s1"))
	b.pretendDown()
	if low, _ := b.livePairNow(); low != "e1" {
		t.Fatalf("setup: the pair names %q, want e1", low)
	}

	if !p.selectEntry("ip", "e2") {
		t.Fatal("could not jump to e2")
	}
	low, _ := b.livePairNow()
	if low == "e1" {
		t.Fatal("the pair still names e1 after the jump to e2 — a verdict arriving now would burn the " +
			"edge the tunnel just left, not the one it is attempting")
	}
	if low != "e2" {
		t.Fatalf("the pair names %q after the jump to e2", low)
	}
	if got := b.readStatus(t).Pair.Low; got != "e2" {
		t.Fatalf("the status file the node reads still says %q", got)
	}
}

// End to end, through the real mailbox and the real poll: the operator names the second address and
// the live tunnel is carrying traffic on it, with a session, shortly after.
func TestAJumpMovesALiveTunnel(t *testing.T) {
	cli, _, _, a2, _, _ := probePair(t, "jumpl")
	writeFileAtomic(cli.st.selectPath(), []byte(`{"kind":"dst","key":"`+a2+`"}`), 0o644)

	deadline := time.Now().Add(15 * time.Second)
	for {
		p := cli.dst()
		if p != nil && p.String() == a2 && cli.session.Load() != nil && cli.peerAnswered.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the manual jump never landed on %s (carrier is on %v)", a2, cli.dst())
		}
		time.Sleep(50 * time.Millisecond)
	}

	if got := cli.pp.current(); got != a2 {
		t.Fatalf("the tunnel is carrying on %s while the pool reports %s", a2, got)
	}
}
