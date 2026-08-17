package packet

import (
	"testing"
	"time"
)

// wakeKeepalive is long enough that sleeping it out is unmistakable next to one round trip on
// loopback, and short enough that five rounds do not dominate the package.
const wakeKeepalive = 6 * time.Second

// wakeBudget is what one round may take end to end: the pin poller's own 1s tick plus a handshake. It
// sits far below wakeKeepalive on purpose — the thing under test is whether the loop waits out the
// sleep it was already in, and the only way to see that is a budget the sleep cannot fit inside.
const wakeBudget = 2 * time.Second

// TestAClearedSessionDoesNotWaitOutTheKeepalive is the class. clientLoop picks the SHORT
// handshake-retransmit interval whenever there is no session — but it picks before it sleeps, so a
// session cleared mid-sleep by the pin poller (a node failover, or the operator's jump) goes unnoticed
// until the sleep ends. The tunnel is then down for a uniformly random slice of a whole keepalive, for
// nothing: the endpoint is already chosen and the handshake is one round trip away.
//
// It drives the real command file, so the parse, the dispatch, the burn, the carrier's rotate and the
// loop's wake are all the production path. FIVE rounds, because one proves nothing about a delay whose
// signature is that it is RANDOM — against untouched code a single round passes about a sixth of the time.
func TestAClearedSessionDoesNotWaitOutTheKeepalive(t *testing.T) {
	cli, _, _, _, _, _ := probePair(t, wakeKeepalive, "wake")
	p := cli.pp

	// settle waits until the tunnel is up AND the loop is back in a LONG sleep. While a handshake is
	// outstanding the loop sleeps the short interval, and a round measured against that would pass with
	// or without the fix.
	settle := func() {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for cli.sealer() == nil || !cli.peerAnswered.Load() {
			if time.Now().After(deadline) {
				t.Fatal("the tunnel never came up between rounds")
			}
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(1200 * time.Millisecond) // past the short interval, so the next verdict lands in the long one
	}

	var worst time.Duration
	for round := 1; round <= 5; round++ {
		settle()
		gone := p.current()
		start := time.Now()
		writeFileAtomic(p.cmdPath(), []byte(`{"cmd":"fail","key":"`+gone+`"}`), 0o644)

		deadline := time.Now().Add(wakeKeepalive + 10*time.Second)
		for p.current() == gone || cli.sealer() == nil {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: the tunnel never re-handshaked after the node's verdict", round)
			}
			time.Sleep(10 * time.Millisecond)
		}
		took := time.Since(start)
		if took > worst {
			worst = took
		}
		t.Logf("round %d: left %s, re-handshaked in %v", round, gone, took.Round(time.Millisecond))
		if took > wakeBudget {
			t.Errorf("round %d: the re-handshake took %v, over the %v budget — the loop slept out its "+
				"keepalive instead of noticing the session had gone",
				round, took.Round(time.Millisecond), wakeBudget)
		}
	}
	t.Logf("worst %v · budget %v · keepalive %v", worst.Round(time.Millisecond), wakeBudget, wakeKeepalive)
}

// TestATimedRotationDoesNotWakeTheLoop is the other side of the gate. A proactive rotation keeps the
// AEAD session on purpose — not one packet is dropped — so there is nothing to re-handshake and nothing
// to wake for. Waking anyway would push a ping out early on every rotate beat: wasted traffic, and a
// timing tell on the one carrier family whose whole point is not having one.
func TestATimedRotationDoesNotWakeTheLoop(t *testing.T) {
	b := &UDP{isClient: true, cryptoOn: true, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.pp = NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0, "")
	defer close(b.closeCh)

	b.rotatePeerUDP(true)
	select {
	case <-b.wake:
		t.Fatal("a timed rotation woke the loop — it keeps its session, so there is nothing to wake for")
	default:
	}

	b.rotatePeerUDP(false)
	select {
	case <-b.wake:
	default:
		t.Fatal("a failover rotation cleared the session and did NOT wake the loop")
	}
}

// TestAPinWakesTheLoop covers the operator's «این را فعال کن» separately: it clears the session on the
// pin poller exactly like a failover, but through adoptPeer* rather than the rotate, so the rotate's
// wake says nothing about it.
func TestAPinWakesTheLoop(t *testing.T) {
	b := &UDP{isClient: true, cryptoOn: true, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.pp = NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0, "")
	defer close(b.closeCh)

	b.adoptPeerUDP()
	select {
	case <-b.wake:
	default:
		t.Fatal("a manual jump cleared the session and did NOT wake the loop")
	}
}

// TestTheWakeIsNilSafeAndCollapses pins the two properties the send relies on: a carrier built without a
// wake channel must not panic (it just sleeps the interval out, as before), and repeated signals must
// not block — the loop needs to know THAT the session went, never how many times.
func TestTheWakeIsNilSafeAndCollapses(t *testing.T) {
	wakeLoop(nil)

	ch := make(chan struct{}, 1)
	for i := 0; i < 100; i++ {
		wakeLoop(ch) // would deadlock on the second if it were a blocking send
	}
	if len(ch) != 1 {
		t.Fatalf("100 signals should collapse to one pending wake, got %d", len(ch))
	}
}
