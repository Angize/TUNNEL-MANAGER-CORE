package dnstun

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"net"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

func TestQueuePacketConnBasicRoundTrip(t *testing.T) {
	var peer ClientID
	peer[0] = 0xAB
	c := NewQueuePacketConn(peer)
	defer c.Close()

	// WriteTo enqueues onto the peer's outgoing queue.
	if _, err := c.WriteTo([]byte("hello"), peer); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	select {
	case got := <-c.OutgoingQueue(peer):
		if string(got) != "hello" {
			t.Fatalf("OutgoingQueue got %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("OutgoingQueue: nothing queued")
	}

	// QueueIncoming feeds a datagram that ReadFrom returns, with its addr.
	c.QueueIncoming([]byte("world"), peer)
	buf := make([]byte, 16)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "world" || addr.String() != peer.String() {
		t.Fatalf("ReadFrom got %q from %v, want world from %v", buf[:n], addr, peer)
	}
}

func TestQueuePacketConnWriteCopiesBuffer(t *testing.T) {
	var peer ClientID
	c := NewQueuePacketConn(peer)
	defer c.Close()
	p := []byte("abc")
	_, _ = c.WriteTo(p, peer)
	p[0] = 'X' // mutate after the write — the queued copy must be unaffected
	got := <-c.OutgoingQueue(peer)
	if string(got) != "abc" {
		t.Fatalf("WriteTo did not copy: got %q", got)
	}
}

func TestQueuePacketConnCloseUnblocksRead(t *testing.T) {
	c := NewQueuePacketConn(ClientID{})
	done := make(chan error, 1)
	go func() {
		_, _, err := c.ReadFrom(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("ReadFrom after Close: err = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

func TestQueueIncomingDropsWhenFull(t *testing.T) {
	c := NewQueuePacketConn(ClientID{})
	defer c.Close()
	// Overfill the recv queue; QueueIncoming must never block or panic.
	for i := 0; i < recvQueueSize+50; i++ {
		c.QueueIncoming([]byte{byte(i)}, ClientID{})
	}
}

// pump moves datagrams from src's outgoing queue (addressed to `via`) into dst as if
// received from `as`, dropping a `lossPct` fraction to simulate an unreliable DNS channel.
// It stops when either conn closes.
func pump(src, dst *QueuePacketConn, via, as net.Addr, lossPct int, rng *mrand.Rand) {
	out := src.OutgoingQueue(via)
	for {
		select {
		case <-src.Closed():
			return
		case <-dst.Closed():
			return
		case buf := <-out:
			if lossPct > 0 && rng.IntN(100) < lossPct {
				continue // drop — kcp-go must recover
			}
			dst.QueueIncoming(buf, as)
		}
	}
}

// TestKCPOverQueueReliableWithLoss is the core Phase-A proof: a real kcp-go session over
// two cross-wired QueuePacketConns delivers a large payload intact IN BOTH DIRECTIONS even
// when a fifth of datagrams are dropped — i.e. the reliability layer the DNS carrier rides
// on actually works over a lossy, socket-less transport. It drives the session FULL-DUPLEX
// (separate read and write goroutines each side), exactly as the real carrier does — never
// io.Copy on a single session, which would read-then-write in one goroutine and self-stall.
func TestKCPOverQueueReliableWithLoss(t *testing.T) {
	const lossPct = 20
	const payloadSize = 32 * 1024 // many datagrams, exercises retransmit/reorder
	// Independent PRNGs per direction: a single *mrand.Rand shared across both pump goroutines
	// would be a data race (math/rand/v2 is not concurrency-safe).
	rngUp := mrand.New(mrand.NewPCG(1, 2))
	rngDown := mrand.New(mrand.NewPCG(3, 4))

	var clientID ClientID
	if _, err := rand.Read(clientID[:]); err != nil {
		t.Fatal(err)
	}
	serverAddr := ClientID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // client's fixed peer key

	clientQPC := NewQueuePacketConn(clientID)
	serverQPC := NewQueuePacketConn(serverAddr)
	defer clientQPC.Close()
	defer serverQPC.Close()

	// Cross-wire with loss: client's sends reach the server keyed by clientID; the server's
	// sends to clientID reach the client keyed by serverAddr (the client side ignores the addr).
	go pump(clientQPC, serverQPC, serverAddr, clientID, lossPct, rngUp)
	go pump(serverQPC, clientQPC, clientID, serverAddr, lossPct, rngDown)

	// Server: accept one session and echo full-duplex (a dedicated read loop that writes each
	// chunk straight back — the write goes out on the same session from this one goroutine, but
	// each Write is a discrete non-blocking-until-window call, not an io.Copy read/write lockstep).
	lis, err := kcp.ServeConn(nil, 0, 0, serverQPC)
	if err != nil {
		t.Fatalf("ServeConn: %v", err)
	}
	go func() {
		sess, err := lis.AcceptKCP()
		if err != nil {
			return
		}
		tuneKCP(sess)
		buf := make([]byte, 4096)
		for {
			n, err := sess.Read(buf)
			if err != nil {
				return
			}
			if _, err := sess.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Client: open the session; write the payload and read the echo in SEPARATE goroutines.
	cli, err := kcp.NewConn2(serverAddr, nil, 0, 0, clientQPC)
	if err != nil {
		t.Fatalf("NewConn2: %v", err)
	}
	tuneKCP(cli)

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() { // reader
		off := 0
		buf := make([]byte, 4096)
		for off < len(got) {
			n, err := cli.Read(buf)
			if err != nil {
				readDone <- err
				return
			}
			copy(got[off:], buf[:n])
			off += n
		}
		readDone <- nil
	}()
	go func() { _, _ = cli.Write(payload) }()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out: reliable stream did not converge under %d%% loss", lossPct)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: the reliable stream corrupted data under %d%% loss", lossPct)
	}
	_ = cli.Close()
}

// tuneKCP applies the low-latency, single-stream settings the DNS carrier uses: turbo mode
// (fast retransmit) so a lossy channel recovers quickly, stream mode (we frame our own
// packets), and a small MTU befitting the tiny effective payload of a DNS message.
func tuneKCP(s *kcp.UDPSession) {
	s.SetStreamMode(true)
	s.SetNoDelay(1, 20, 2, 1)
	s.SetWindowSize(256, 256)
	s.SetMtu(220)
}
