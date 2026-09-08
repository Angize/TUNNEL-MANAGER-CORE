//go:build linux

package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// Every carrier samples the rotation deadline on the same one-second tick.
//
// It did not used to. udp and raw called rc.proactive from their keepalive loop, which waits
// keepaliveInterval(10s, psk) -- 8.5 to 12 seconds with the jitter -- so a rotation that came due was
// served up to twelve seconds late. The TCP family had a second one-second goroutine of its own. Now
// all three drive it from runCmdPoll, so a two-second period is served inside four seconds on every
// carrier. A regression that puts proactive back on the keepalive loop fails this within the budget.
func TestEveryCarrierServesItsRotationDeadlineWithinASecond(t *testing.T) {
	const period = 2 * time.Second
	const budget = 5 * time.Second

	for _, c := range []struct {
		name  string
		build func(t *testing.T) (*PeerPool, func())
	}{
		{"udp", buildTickUDP},
		{"raw", buildTickRaw},
		{"tcp", buildTickTCP},
		{"ws", buildTickWS},
	} {
		t.Run(c.name, func(t *testing.T) {
			pool, start := c.build(t)
			if pool.rotate != period {
				t.Fatalf("the pool was built with a rotation period of %v, not %v", pool.rotate, period)
			}
			at := pool.activeIdx()
			start()

			deadline := time.Now().Add(budget)
			for time.Now().Before(deadline) {
				if pool.activeIdx() != at {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			t.Fatalf("a %v rotation period was still unserved %v later — the deadline is not being "+
				"sampled on the one-second tick", period, budget)
		})
	}
}

func tickStatus(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "core.status")
}

func buildTickUDP(t *testing.T) (*PeerPool, func()) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b := &UDP{isClient: true, wake: make(chan struct{}, 1), closeCh: make(chan struct{})}
	b.conn.Store(c)
	b.SetStatusPath(tickStatus(t))
	b.soloPeer.Store(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5555})
	b.SetPeerPool(NewPeerPool(rigDsts, 2*time.Second))
	rc := b.newController()
	t.Cleanup(func() { close(b.closeCh) })
	return b.pp, func() { go b.cmdPollLoop(rc) }
}

func buildTickRaw(t *testing.T) (*PeerPool, func()) {
	t.Helper()
	r := &Raw{isClient: true, profile: "udp", psk: rigPSK,
		wake: make(chan struct{}, 1), closeCh: make(chan struct{})}
	r.SetStatusPath(tickStatus(t))
	r.SetPeerPool(NewPeerPool(rigDsts, 2*time.Second))
	rc := newRotationController(r.pp, r.sp)
	rc.attachStatus(r.st)
	t.Cleanup(func() { close(r.closeCh) })
	return r.pp, func() { go r.cmdPollLoop(rc) }
}

func buildTickTCP(t *testing.T) (*PeerPool, func()) {
	t.Helper()
	b := &TCP{isClient: true, closeCh: make(chan struct{})}
	b.SetStatusPath(tickStatus(t))
	b.SetPeerPool(NewPeerPool(rigDsts, 2*time.Second))
	t.Cleanup(func() { close(b.closeCh) })
	return b.pp, func() { go runCmdPoll(b.closeCh, b.cmdPollTick) }
}

func buildTickWS(t *testing.T) (*PeerPool, func()) {
	t.Helper()
	b := edgeTCP(rigDsts, snis("front-a", "front-b"), 2*time.Second)
	b.SetStatusPath(tickStatus(t))
	t.Cleanup(func() { close(b.closeCh) })
	return b.pp, func() { go runCmdPoll(b.closeCh, b.cmdPollTick) }
}
