package packet

import (
	"net"
	"testing"
	"time"
)

// TestOnlyTheLiveCarrierStampsHeartbeat pins who is allowed to move the tunnel's heartbeat.
//
// Under warm standby every carrier runs its own readLoop and keepaliveLoop pings the STANDBY as well as
// the active, so an unguarded stamp let the standby's pongs keep hb fresh with an empty active slot —
// exactly the state an operator pin onto an edge that will not come up produces. The panel then read the
// tunnel green for the whole pin_ttl while every packet was being dropped.
//
// Driven at the readLoop level over net.Pipe: no TUN, no listener, no timing assumptions beyond a poll.
func TestOnlyTheLiveCarrierStampsHeartbeat(t *testing.T) {
	b := &TCP{isClient: true, warmStandby: true, keepalive: time.Second, idle: 5 * time.Second,
		closeCh: make(chan struct{})}

	activeConn, activePeer := net.Pipe()
	standbyConn, standbyPeer := net.Pipe()
	t.Cleanup(func() {
		close(b.closeCh)
		activeConn.Close()
		activePeer.Close()
		standbyConn.Close()
		standbyPeer.Close()
	})

	active := b.newFramer(activeConn)
	standby := b.newFramer(standbyConn)
	activeWire := b.newFramer(activePeer)   // the far end of each carrier, standing in for the server
	standbyWire := b.newFramer(standbyPeer) //

	// Both carriers are up and read by their own goroutine, as the warm-standby manager runs them; only
	// one of them is the live one (b.cur is published before its reader starts, on every client path).
	b.cur.Store(active)
	b.standby.Store(standby)
	go b.readLoop(active)
	go b.readLoop(standby)

	// The standby answers its keepalive. unanswered is the synchronisation point: readLoop clears it on
	// the line above the stamp, so once it reads 0 the stamp has been reached and skipped.
	standby.unanswered.Store(1)
	if err := standbyWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write standby pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the standby reader consumed its pong", func() bool {
		return standby.unanswered.Load() == 0
	})
	time.Sleep(50 * time.Millisecond) // an unguarded stamp would have landed long before this
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("a warm standby's pong stamped the tunnel heartbeat (hb=%d) — the panel reads green with no live carrier", hb)
	}

	// The LIVE carrier's own pong must still stamp it, or an idle tunnel would age to red.
	if err := activeWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write active pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the live carrier stamped the heartbeat", func() bool {
		return b.lastRx.Load() != 0
	})

	// And a promoted standby counts from the moment it becomes live (promote stores b.cur while the
	// standby's reader is already running — the case the guard must not break).
	promotedAt := b.lastRx.Load()
	b.cur.Store(standby)
	if err := standbyWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write promoted-standby pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the promoted standby stamps the heartbeat", func() bool {
		return b.lastRx.Load() > promotedAt
	})
}

// TestGoingLiveAdoptsTheCarriersOwnHeartbeat covers the other half of the same rule: a carrier that is
// not the tunnel's records its liveness on ITSELF (cf.rxAt) — the crypto handshake and every pong it
// answers as a standby — and the tunnel adopts that only when the carrier actually goes live.
//
// Without the split, building such a carrier stamped the tunnel: every warm-standby rebuild and every
// parked rotation carrier reset the tunnel's age to zero and bought a dead tunnel another dead-window of
// green. With it, hb still jumps the instant the carrier is promoted — from the proof it already had, not
// from a fabricated "now" — so nothing waits for the next keepalive to go green.
func TestGoingLiveAdoptsTheCarriersOwnHeartbeat(t *testing.T) {
	b := &TCP{isClient: true, warmStandby: true, keepalive: time.Second, idle: 5 * time.Second,
		closeCh: make(chan struct{})}

	standbyConn, standbyPeer := net.Pipe()
	t.Cleanup(func() {
		close(b.closeCh)
		standbyConn.Close()
		standbyPeer.Close()
	})
	standby := b.newFramer(standbyConn)
	standbyWire := b.newFramer(standbyPeer)

	// A carrier built while the tunnel has no live one at all — exactly what warmEstablish(standby) and
	// buildWarm produce. Its handshake proof lands on the connection.
	handshake := time.Now().UnixNano()
	standby.rxAt.Store(handshake)
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("building a carrier moved the tunnel heartbeat (hb=%d) before it was ever live", hb)
	}

	// It answers keepalives for a while, still not the tunnel's carrier.
	go b.readLoop(standby)
	if err := standbyWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write standby pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the standby recorded its own liveness", func() bool {
		return standby.rxAt.Load() > handshake
	})
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("a standby's pong moved the tunnel heartbeat (hb=%d) with no live carrier", hb)
	}

	// Promotion: the tunnel adopts what the carrier already proved, with no wait for its next frame.
	own := standby.rxAt.Load()
	b.cur.Store(standby)
	b.adoptRx(standby)
	if hb := b.lastRx.Load(); hb != own {
		t.Fatalf("a promoted carrier must publish its own last inbound frame: hb=%d, carrier=%d", hb, own)
	}

	// And hb never walks backwards — a standby built minutes ago must not age a tunnel whose outgoing
	// active was receiving until a moment before it died.
	newer := own + int64(time.Second)
	b.lastRx.Store(newer)
	b.adoptRx(standby)
	if hb := b.lastRx.Load(); hb != newer {
		t.Fatalf("adopting an older carrier moved the heartbeat backwards: hb=%d, want %d", hb, newer)
	}
}
