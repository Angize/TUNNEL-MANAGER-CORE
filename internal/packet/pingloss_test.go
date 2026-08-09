package packet

import (
	"bufio"
	"net"
	"testing"
)

// ping_loss_threshold is the operator-facing promise «how many keepalives may go unanswered in a row
// before the connection is dropped». Keeping that promise means every ping the threshold pays for has
// to be given a chance: the counter is tested BEFORE a send, never after it.
//
// Counting after the write charges the connection for a ping that left microseconds ago, so a
// threshold of N buys N-1 real chances — and N=1, which the panel allows, drops a perfectly healthy
// connection the instant its first keepalive is written, every keepalive interval, forever.
//
// This matters most exactly where it is hardest to see: in a one-way blackhole (data still flowing
// out, nothing coming back) the idle reaper never fires, because a successful outbound write also
// refreshes the read deadline. The ping counter is then the ONLY thing that notices.

// pingRun drives pingOne the way keepaliveLoop does — send, and on the next tick send again — and
// counts the pings that were given an interval in which they could be answered. A ping written and
// then immediately charged against the threshold is NOT one of them, which is the whole distinction.
func pingRun(t *testing.T, threshold int32) (chances int) {
	t.Helper()
	old := pingLossThreshold
	pingLossThreshold = threshold
	defer func() { pingLossThreshold = old }()

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	// Drain the peer end so writeFrame never blocks on net.Pipe's synchronous semantics.
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
	for i := 0; i < 100; i++ { // bounded: a threshold that never trips is itself the failure
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

// N in the setting must buy N pings on the wire, each with an interval in which it could be answered.
func TestPingLossThresholdPaysForEveryPingItPromises(t *testing.T) {
	for _, threshold := range []int32{1, 2, 3, 5, 10} {
		if got := pingRun(t, threshold); int32(got) != threshold {
			t.Errorf("ping_loss_threshold=%d gave the peer %d chance(s) to answer, not %d — the last ping it "+
				"paid for was charged the instant it was written, with no interval to be answered in",
				threshold, got, threshold)
		}
	}
}

// The floor is the case that bites: at 1 the connection must still send its one ping and survive that
// round, or it drops every keepalive interval on a link that is perfectly healthy.
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
	// An answer arrives before the next tick: readLoop clears the counter, and the tunnel lives on.
	cf.unanswered.Store(0)
	if ok, _ := b.pingOne(cf); !ok {
		t.Fatal("an answered ping still dropped the connection")
	}
	// No answer this time: the next tick is where it is allowed to give up.
	if ok, err := b.pingOne(cf); ok || err != errPingTimeout {
		t.Fatalf("an unanswered ping did not end the round: ok=%v err=%v", ok, err)
	}
}

// A fresh inbound frame is what makes the count mean "consecutive": without the reset a long-lived
// tunnel would accumulate pings and eventually drop itself for no reason at all.
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
		cf.unanswered.Store(0) // what readLoop does on any fresh frame
	}
}
