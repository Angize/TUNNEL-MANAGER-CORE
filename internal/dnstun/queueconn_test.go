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
	p[0] = 'X'
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

	for i := 0; i < recvQueueSize+50; i++ {
		c.QueueIncoming([]byte{byte(i)}, ClientID{})
	}
}

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
				continue
			}
			dst.QueueIncoming(buf, as)
		}
	}
}

func TestKCPOverQueueReliableWithLoss(t *testing.T) {
	const lossPct = 20
	const payloadSize = 32 * 1024

	rngUp := mrand.New(mrand.NewPCG(1, 2))
	rngDown := mrand.New(mrand.NewPCG(3, 4))

	var clientID ClientID
	if _, err := rand.Read(clientID[:]); err != nil {
		t.Fatal(err)
	}
	serverAddr := ClientID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	clientQPC := NewQueuePacketConn(clientID)
	serverQPC := NewQueuePacketConn(serverAddr)
	defer clientQPC.Close()
	defer serverQPC.Close()

	go pump(clientQPC, serverQPC, serverAddr, clientID, lossPct, rngUp)
	go pump(serverQPC, clientQPC, clientID, serverAddr, lossPct, rngDown)

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
	go func() {
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

func tuneKCP(s *kcp.UDPSession) {
	s.SetStreamMode(true)
	s.SetNoDelay(1, 20, 2, 1)
	s.SetWindowSize(256, 256)
	s.SetMtu(220)
}
