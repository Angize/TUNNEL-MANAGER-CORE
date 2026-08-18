package packet

import (
	"bufio"
	"net"
	"testing"
)

func pingRun(t *testing.T, threshold int32) (chances int) {
	t.Helper()
	old := pingLossThreshold
	pingLossThreshold = threshold
	defer func() { pingLossThreshold = old }()

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := s.Read(buf); err != nil {
				return
			}
		}
	}()

	cf := &connFramer{conn: c, r: bufio.NewReaderSize(c, maxFrame+2)}
	b := &TCP{}
	for i := 0; i < 100; i++ {
		ok, err := b.pingOne(cf)
		if !ok {
			if err != errPingTimeout {
				t.Fatalf("threshold %d: gave up with %v, want errPingTimeout", threshold, err)
			}
			return chances
		}
		chances++
	}
	t.Fatalf("threshold %d: never gave up after 100 pings", threshold)
	return 0
}

func TestPingLossThresholdPaysForEveryPingItPromises(t *testing.T) {
	for _, threshold := range []int32{1, 2, 3, 5, 10} {
		if got := pingRun(t, threshold); int32(got) != threshold {
			t.Errorf("ping_loss_threshold=%d gave the peer %d chance(s) to answer, not %d — the last ping it "+
				"paid for was charged the instant it was written, with no interval to be answered in",
				threshold, got, threshold)
		}
	}
}

func TestAThresholdOfOneStillSendsItsPingAndSurvivesTheRound(t *testing.T) {
	old := pingLossThreshold
	pingLossThreshold = 1
	defer func() { pingLossThreshold = old }()

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := s.Read(buf); err != nil {
				return
			}
		}
	}()
	cf := &connFramer{conn: c, r: bufio.NewReaderSize(c, maxFrame+2)}
	b := &TCP{}

	if ok, err := b.pingOne(cf); !ok {
		t.Fatalf("the FIRST ping already dropped the connection (err %v) — nothing had a chance to answer", err)
	}

	cf.unanswered.Store(0)
	if ok, _ := b.pingOne(cf); !ok {
		t.Fatal("an answered ping still dropped the connection")
	}

	if ok, err := b.pingOne(cf); ok || err != errPingTimeout {
		t.Fatalf("an unanswered ping did not end the round: ok=%v err=%v", ok, err)
	}
}

func TestAnInboundFrameClearsTheCount(t *testing.T) {
	old := pingLossThreshold
	pingLossThreshold = 3
	defer func() { pingLossThreshold = old }()

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := s.Read(buf); err != nil {
				return
			}
		}
	}()
	cf := &connFramer{conn: c, r: bufio.NewReaderSize(c, maxFrame+2)}
	b := &TCP{}

	for i := 0; i < 50; i++ {
		if ok, err := b.pingOne(cf); !ok {
			t.Fatalf("round %d: dropped (%v) although every ping was answered", i, err)
		}
		cf.unanswered.Store(0)
	}
}
