package packet

import (
	"net"
	"testing"
	"time"
)

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
	other := b.newFramer(otherConn)
	liveWire := b.newFramer(livePeer)
	otherWire := b.newFramer(otherPeer)

	b.cur.Store(live)
	go b.readLoop(live)
	go b.readLoop(other)

	other.unanswered.Store(1)
	if err := otherWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write other pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the other reader consumed its pong", func() bool {
		return other.unanswered.Load() == 0
	})
	time.Sleep(50 * time.Millisecond)
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("a connection that is not the live one stamped the tunnel heartbeat (hb=%d) — the panel "+
			"reads green with no live carrier", hb)
	}

	if err := liveWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write live pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the live carrier stamped the heartbeat", func() bool {
		return b.lastRx.Load() != 0
	})

	wentLiveAt := b.lastRx.Load()
	b.cur.Store(other)
	if err := otherWire.writeFrame(typePong, nil); err != nil {
		t.Fatalf("write newly-live pong: %v", err)
	}
	waitFor(t, 4*time.Second, "the newly-live carrier stamps the heartbeat", func() bool {
		return b.lastRx.Load() > wentLiveAt
	})
}

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

	handshake := time.Now().UnixNano()
	cf.rxAt.Store(handshake)
	if hb := b.lastRx.Load(); hb != 0 {
		t.Fatalf("building a carrier moved the tunnel heartbeat (hb=%d) before it was ever live", hb)
	}

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

	own := cf.rxAt.Load()
	b.cur.Store(cf)
	b.adoptRx(cf)
	if hb := b.lastRx.Load(); hb != own {
		t.Fatalf("a carrier that went live must publish its own last inbound frame: hb=%d, carrier=%d", hb, own)
	}

	newer := own + int64(time.Second)
	b.lastRx.Store(newer)
	b.adoptRx(cf)
	if hb := b.lastRx.Load(); hb != newer {
		t.Fatalf("adopting an older carrier moved the heartbeat backwards: hb=%d, want %d", hb, newer)
	}
}
