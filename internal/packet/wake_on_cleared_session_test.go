package packet

import (
	"testing"
	"time"
)

const wakeKeepalive = 6 * time.Second

const wakeBudget = 2 * time.Second

func TestAClearedSessionDoesNotWaitOutTheKeepalive(t *testing.T) {
	cli, _, _, _, _, _ := probePair(t, "wake")
	p := cli.pp

	settle := func() {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for cli.sealer() == nil || !cli.peerAnswered.Load() {
			if time.Now().After(deadline) {
				t.Fatal("the tunnel never came up between rounds")
			}
			time.Sleep(20 * time.Millisecond)
		}

		liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdOK, Low: p.current()})
		time.Sleep(1200 * time.Millisecond)
	}

	var worst time.Duration
	for round := 1; round <= 5; round++ {
		settle()
		gone := p.current()

		spendThePortRung(t, cli, func() {
			liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail, Low: gone})
		})

		was := cli.session.Load()
		start := time.Now()
		liveVerdict(t, cli.st.verdictPath(), settledEpoch(t, cli.st), poolCmd{Cmd: cmdFail, Low: gone})

		deadline := time.Now().Add(wakeKeepalive + 10*time.Second)
		for cli.session.Load() == was || cli.sealer() == nil {
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

func TestATimedRotationDoesNotWakeTheLoop(t *testing.T) {
	b := &UDP{isClient: true, cryptoOn: true, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.pp = NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0)
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

func TestAPinWakesTheLoop(t *testing.T) {
	b := &UDP{isClient: true, cryptoOn: true, closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.pp = NewPeerPool([]string{"10.0.0.1:9", "10.0.0.2:9"}, 0)
	defer close(b.closeCh)

	b.adoptPeerUDP()
	select {
	case <-b.wake:
	default:
		t.Fatal("a manual jump cleared the session and did NOT wake the loop")
	}
}

func TestTheWakeIsNilSafeAndCollapses(t *testing.T) {
	wakeLoop(nil)

	ch := make(chan struct{}, 1)
	for i := 0; i < 100; i++ {
		wakeLoop(ch)
	}
	if len(ch) != 1 {
		t.Fatalf("100 signals should collapse to one pending wake, got %d", len(ch))
	}
}
