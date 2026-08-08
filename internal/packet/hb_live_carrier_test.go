package packet

import (
	"net"
	"testing"
	"time"
)

// Who may move the TUNNEL's heartbeat, when more than one connection is alive at once. That happens on
// every reconnect -- the server keeps the previous conn registered until it times out, and the client's
// old reader has not exited yet -- so "the connection answered" and "the tunnel is carrying" are two
// different facts and only the second may be published.
//
// Get it wrong and hb stays fresh off a connection that is NOT the live one, which reads GREEN on the
// panel with an empty active slot: exactly the state an operator pin onto an edge that will not come up
// produces. Driven at the readLoop level over net.Pipe.
func TestOnlyTheLiveCarrierStampsHeartbeat(t *testing.T) {
	b := &TCP{isClient: true, keepalive: time.Second, idle: 5 * time.Second,
		closeCh: make(chan struct{})}

	liveConn, livePeer := net.Pipe()
	otherConn, otherPeer := net.Pipe()
	t.Cleanup(func() {
		close(b.closeCh)
		liveConn.Close()
		livePeer.Close()
		otherConn.Close()
		otherPeer.Close()
	})

	live := b.newFramer(liveConn)
	other := b.newFramer(otherConn)   // a second authenticated connection that is NOT b.cur
	liveWire := b.newFramer(livePeer) // the far end of each, standing in for the server
	otherWire := b.newFramer(otherPeer)

	// Both are read by their own goroutine; only one of them is the tunnel's (b.cur is published before
	// its reader starts, on every client path).
	b.cur.Store(live)
	go b.readLoop(live)
	go b.readLoop(other)

	// The other connection answers a keepalive. unanswered is the synchronisation point: readLoop clears
	// it on the line above the stamp, so once it reads 0 the stamp has been reached and skipped.
	other.unanswered.Store(1)
	if err := otherWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write other pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the other reader consumed its pong", func() bool {
		return other.unanswered.Load() == 0
	})
	time.Sleep(50 * time.Millisecond) // an unguarded stamp would have landed long before this
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("a connection that is not the live one stamped the tunnel heartbeat (hb=%d) — the panel "+
			"reads green with no live carrier", hb)
	}

	// The LIVE carrier's own pong must still stamp it, or an idle tunnel would age to red.
	if err := liveWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write live pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the live carrier stamped the heartbeat", func() bool {
		return b.lastRx.Load() != 0
	})

	// ...and when the OTHER one becomes live, it counts from that moment — b.cur is stored while its
	// reader is already running, which is the case the guard must not break.
	wentLiveAt := b.lastRx.Load()
	b.cur.Store(other)
	if err := otherWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write newly-live pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the newly-live carrier stamps the heartbeat", func() bool {
		return b.lastRx.Load() > wentLiveAt
	})
}

// The other half of the rule: a connection that is not the tunnel's records liveness on ITSELF
// (cf.rxAt) -- its handshake, and every pong it answers -- and the tunnel adopts that only when the
// connection actually goes live. Without the split, every re-dial reset the tunnel's age and bought a
// dead tunnel another dead-window of green.
func TestGoingLiveAdoptsTheCarriersOwnHeartbeat(t *testing.T) {
	b := &TCP{isClient: true, keepalive: time.Second, idle: 5 * time.Second,
		closeCh: make(chan struct{})}

	conn, peer := net.Pipe()
	t.Cleanup(func() {
		close(b.closeCh)
		conn.Close()
		peer.Close()
	})
	cf := b.newFramer(conn)
	wire := b.newFramer(peer)

	// A connection built while the tunnel has no live one at all. Its handshake proof lands on the
	// connection, not on the tunnel.
	handshake := time.Now().UnixNano()
	cf.rxAt.Store(handshake)
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("building a carrier moved the tunnel heartbeat (hb=%d) before it was ever live", hb)
	}

	// It answers keepalives for a while, still not the tunnel's carrier.
	go b.readLoop(cf)
	if err := wire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the connection recorded its own liveness", func() bool {
		return cf.rxAt.Load() > handshake
	})
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("a pong on a non-live connection moved the tunnel heartbeat (hb=%d)", hb)
	}

	// Going live: the tunnel adopts what the connection already proved, with no wait for its next frame.
	own := cf.rxAt.Load()
	b.cur.Store(cf)
	b.adoptRx(cf)
	if hb := b.lastRx.Load(); hb != own {
		t.Fatalf("a carrier that went live must publish its own last inbound frame: hb=%d, carrier=%d", hb, own)
	}

	// And hb never walks backwards — a connection built minutes ago must not age a tunnel whose outgoing
	// carrier was receiving until a moment before it died.
	newer := own + int64(time.Second)
	b.lastRx.Store(newer)
	b.adoptRx(cf)
	if hb := b.lastRx.Load(); hb != newer {
		t.Fatalf("adopting an older carrier moved the heartbeat backwards: hb=%d, want %d", hb, newer)
	}
}
