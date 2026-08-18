package packet

import (
	"testing"
	"time"
)

// TestNoClockGivesUpTheSession is the class, and it is a negative control: nothing may re-handshake a
// crypto client except the judge.
//
// A carrier used to hand its session back on a timer of its own -- one dead window of silence and it
// re-handshaked, whatever the probe had measured. Two things are wrong with that. It is a second hand on
// the wheel, moving the tunnel while the node is mid-experiment on it; and it fires on the wrong
// evidence, because the silence it measures is our own keepalives failing to come back, which a path
// that answers everything and carries nothing never produces.
//
// Driven through Run() on a real pair, because the timer lived inside the client loop and a test that
// called the predicate would have said nothing about the loop that consulted it. The peer is silenced
// and NO verdict is written, so a session that goes missing here went missing on a clock.
func TestNoClockGivesUpTheSession(t *testing.T) {
	const ka = time.Second // deadWindow(ka) = 3s, so the watch below spans several of them
	cli, srv, _ := poollessClient(t, ka, "noclock")

	for cli.sealer() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	was := cli.session.Load()

	// Exactly what the clock existed to notice: the far end stops answering and cannot be told from a
	// peer that restarted. The socket is unconnected, so no ICMP comes back to end the read loop -- the
	// client simply hears nothing, which is the whole input the timer ever had.
	srv.Close()

	silent := 3 * deadWindow(ka)
	start := time.Now()
	for time.Since(start) < silent {
		if cli.session.Load() != was || cli.sealer() == nil {
			t.Fatalf("the session was given up %v after the peer went silent and no verdict asked for it "+
				"-- something is still re-handshaking on a clock (dead window %v)",
				time.Since(start).Round(time.Millisecond), deadWindow(ka))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
