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

func spendTheRungs(t *testing.T, b *TCP) {
	t.Helper()
	for i := 1; i <= portTries; i++ {
		liveVerdict(t, b.st.verdictPath(), b.st.pathEpoch(), poolCmd{Cmd: cmdFail})
		waitFor(t, 20*time.Second, "the ladder to spend free rung "+string(rune('0'+i)), func() bool {
			return rungSpent(b) >= i
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
func TestALongLivedConnectionDoesNotResetTheLadder(t *testing.T) {
	was := minLiveness
	minLiveness = 150 * time.Millisecond
	t.Cleanup(func() { minLiveness = was })

	cli, _ := wsPoolClient(t, "lrst", []string{"h1"}, freeTCPPort(t))
	waitFor(t, 20*time.Second, "the client to connect", func() bool { return cli.curConn.Load() != nil })
	spendTheRungs(t, cli)

	cc := cli.curConn.Load()
	born := time.Now()
	time.Sleep(4 * minLiveness)
	(*cc).Close()
	waitFor(t, 20*time.Second, "the carrier to come back", func() bool {
		c := cli.curConn.Load()
		return c != nil && c != cc
	})
	lived := time.Since(born)

	if got := rungSpent(cli); got != portTries {
		t.Fatalf("a connection that lived %v (min_liveness is %v) put the rung budget back to %d of %d. "+
			"Nothing judged that tunnel -- no probe verdict, no operator -- so the climb the node had "+
			"paid for is gone, and the next outage starts from the bottom again", lived, minLiveness,
			portTries-got, portTries)
	}
}

// The other half of the same rule: the node's ok is what refills it, on the TCP family exactly as on
// udp and raw. Without this the test above would pass on a ladder that can never be reset at all.
func TestTheNodesOkStillRefillsTheLadder(t *testing.T) {
	cli, pool := wsPoolClient(t, "lrok", []string{"h1"}, freeTCPPort(t))
	waitFor(t, 20*time.Second, "the client to connect", func() bool { return cli.curConn.Load() != nil })
	spendTheRungs(t, cli)

	ip, sni, _ := pool.current()
	liveVerdict(t, cli.st.verdictPath(), cli.st.pathEpoch(),
		poolCmd{Cmd: cmdOK, Low: ip, High: sni.host})
	waitFor(t, 20*time.Second, "the ok verdict to refill the ladder", func() bool { return rungSpent(cli) == 0 })
}
