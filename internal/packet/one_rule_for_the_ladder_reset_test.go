//go:build linux

package packet

import (
	"testing"
	"time"
)

func rungSpent(b *TCP) int {
	b.rc.port.mu.Lock()
	defer b.rc.port.mu.Unlock()
	return b.rc.port.spent
}

// A verdict every sweep until the rung is actually spent, which is how the node sends one. A single
// write loses a race it cannot see: spending a port rung IS a carrier drop, the redial bumps the path
// epoch, and the verdict written a moment before then arrives stale and is dropped on the floor.
// Measured under -race on this tree and the one before it: about one run in four lost that race and
// then sat out the full 20s waiting for a rung that nothing was going to spend.
func spendTheRungs(t *testing.T, b *TCP) {
	t.Helper()
	for i := 1; i <= portTries; i++ {
		waitFor(t, 20*time.Second, "the ladder to spend free rung "+string(rune('0'+i)), func() bool {
			if rungSpent(b) >= i {
				return true
			}
			liveVerdict(t, b.st.verdictPath(), b.st.pathEpoch(), poolCmd{Cmd: cmdFail})
			return false
		})
	}
}

// udp and raw reset their ladder only when the node's tun probe says the tunnel is carrying, or when
// the operator picks an endpoint by hand. The TCP family had a third way in: any connection that
// outlived min_liveness called endRound and wiped the whole climb -- the accusation, the revive
// escalation and both rung budgets.
//
// That is the wrong signal on the carrier where it fires most. A filtered edge completes TLS, the
// WebSocket upgrade and the crypto handshake, carries nothing, and dies on the 60s read deadline.
// Sixty seconds clears twenty, so every cycle wiped the ladder and re-armed the revive clock at its
// first tier: the tunnel could climb for an hour and never leave the edge it was stuck on.
//
// One rule for every carrier now: the ladder is reset by the node's verdict, or by the operator.
// Nothing about how long a connection lived is an input any more, so this holds for a connection of
// any age -- there is no threshold left to tune it against.
func TestALongLivedConnectionDoesNotResetTheLadder(t *testing.T) {
	const lifetime = 600 * time.Millisecond

	cli, _ := wsPoolClient(t, "lrst", []string{"h1"}, freeTCPPort(t))
	waitFor(t, 20*time.Second, "the client to connect", func() bool { return cli.curConn.Load() != nil })
	spendTheRungs(t, cli)

	// Spending a port rung IS a carrier drop, so the client is mid-redial the moment the last one lands.
	// Grabbing curConn here without waiting loads a nil pointer and the Close below dereferences it --
	// measured at 1 run in 6 under -race, on this tree and on the one before it.
	waitFor(t, 20*time.Second, "the carrier back up after the rungs were spent", func() bool {
		return cli.curConn.Load() != nil
	})

	cc := cli.curConn.Load()
	born := time.Now()
	time.Sleep(lifetime)
	(*cc).Close()
	waitFor(t, 20*time.Second, "the carrier to come back", func() bool {
		c := cli.curConn.Load()
		return c != nil && c != cc
	})
	lived := time.Since(born)

	if got := rungSpent(cli); got != portTries {
		t.Fatalf("a connection that lived %v put the rung budget back to %d of %d. Nothing judged that "+
			"tunnel -- no probe verdict, no operator -- so the climb the node had paid for is gone, "+
			"and the next outage starts from the bottom again", lived, portTries-got, portTries)
	}
}

// The other half of the same rule: the node's ok is what refills it, on the TCP family exactly as on
// udp and raw. Without this the test above would pass on a ladder that can never be reset at all.
func TestTheNodesOkStillRefillsTheLadder(t *testing.T) {
	cli, _ := wsPoolClient(t, "lrok", []string{"h1"}, freeTCPPort(t))
	waitFor(t, 20*time.Second, "the client to connect", func() bool { return cli.curConn.Load() != nil })
	spendTheRungs(t, cli)

	ip, sni, _ := cli.edgeCombo()
	liveVerdict(t, cli.st.verdictPath(), cli.st.pathEpoch(),
		poolCmd{Cmd: cmdOK, Low: ip, High: sni.host})
	waitFor(t, 20*time.Second, "the ok verdict to refill the ladder", func() bool { return rungSpent(cli) == 0 })
}
