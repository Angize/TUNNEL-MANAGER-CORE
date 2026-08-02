package packet

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countingRelay forwards a connection to target and counts the bytes the CLIENT has put on the wire.
// It counts them as it READS them, i.e. at the earliest possible moment — so "0" really means we had
// not sent anything yet, with no timing slack in our favour.
type countingRelay struct {
	ln net.Listener
	up atomic.Int64
}

func newCountingRelay(t *testing.T, target string) *countingRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &countingRelay{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go r.pipe(c, target)
		}
	}()
	return r
}

func (r *countingRelay) addr() string { return r.ln.Addr().String() }

func (r *countingRelay) pipe(cli net.Conn, target string) {
	srv, err := net.Dial("tcp", target)
	if err != nil {
		cli.Close()
		return
	}
	go func() {
		io.Copy(cli, srv)
		cli.Close()
		srv.Close()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, rerr := cli.Read(buf)
		if n > 0 {
			r.up.Add(int64(n))
			if _, werr := srv.Write(buf[:n]); werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	cli.Close()
	srv.Close()
}

// assertDecoysFirst drives the REAL dial sequence — dialCarrier then handshakeAndPrime, exactly as
// dialLoop, warmEstablish and the single-edge retest dial do — and asserts the decoy injection
// happened before a single byte of ours reached the wire.
func assertDecoysFirst(t *testing.T, b *TCP, relay *countingRelay) {
	t.Helper()
	var calls int
	var already int64
	var got net.Conn
	b.dsWatch = func(c net.Conn) {
		calls++
		already = relay.up.Load()
		got = c
	}
	conn, _, _, err := b.dialCarrier(false)
	if err != nil {
		t.Fatalf("dialCarrier: %v", err)
	}
	defer conn.Close()
	if _, err := b.handshakeAndPrime(conn); err != nil {
		t.Fatalf("handshakeAndPrime: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the decoy injection ran %d times for one dial, want exactly 1", calls)
	}
	if already != 0 {
		t.Fatalf("the decoys were injected AFTER %d bytes of ours were already on the wire: a DPI has "+
			"seen the very handshake the decoys exist to desync it about before the first decoy lands",
			already)
	}
	if _, ok := got.(*net.TCPConn); !ok {
		t.Fatalf("the decoys were mirrored off a %T instead of the bare kernel socket — anything "+
			"wrapped means that layer's handshake had already run", got)
	}
}

// TestDesyncDecoysGoOutBeforeAnyOfOurBytes pins where fake_desync fires: on the bare 4-tuple, before the
// cover handshake or the WebSocket upgrade the decoys are meant to hide. The ordering is not visible in
// the byte stream — decoys leave via AF_PACKET, not through the conn — so the test observes the injection
// point (b.dsWatch) and asks how many of our bytes were on the wire. Real injection stays off.
func TestDesyncDecoysGoOutBeforeAnyOfOurBytes(t *testing.T) {
	const psk = "desync-order-pre-shared-key-12345"
	const cipher = "aes-256-gcm"
	const ka = time.Second

	t.Run("ws", func(t *testing.T) {
		srvDev, _ := tunPair(t, "dsows")
		addr := freeTCPPort(t)
		srv, err := ListenWS(addr, srvDev, ka, false, true, psk, cipher, "")
		if err != nil {
			t.Fatalf("ListenWS: %v", err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })

		relay := newCountingRelay(t, addr)
		cliDev, _ := tunPair(t, "dsowc")
		cli, err := DialWS(relay.addr(), cliDev, ka, false, true, psk, cipher, "", "", false, nil)
		if err != nil {
			t.Fatalf("DialWS: %v", err)
		}
		assertDecoysFirst(t, cli, relay)
	})

	t.Run("tcp+cover", func(t *testing.T) {
		srvDev, _ := tunPair(t, "dsocs")
		addr := freeTCPPort(t)
		srv, err := ListenTCP([]string{addr}, srvDev, ka, false, true, psk, cipher, true, "cover.example")
		if err != nil {
			t.Fatalf("ListenTCP cover: %v", err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })

		relay := newCountingRelay(t, addr)
		cliDev, _ := tunPair(t, "dsocc")
		cli, err := DialTCP(relay.addr(), cliDev, ka, false, true, psk, cipher, true, "cover.example")
		if err != nil {
			t.Fatalf("DialTCP cover: %v", err)
		}
		assertDecoysFirst(t, cli, relay)
	})

	// Plain tcp was already correct — it is here so a future change cannot quietly break the one
	// carrier that never had the bug.
	t.Run("plain tcp", func(t *testing.T) {
		srvDev, _ := tunPair(t, "dsops")
		addr := freeTCPPort(t)
		srv, err := ListenTCP([]string{addr}, srvDev, ka, false, true, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })

		relay := newCountingRelay(t, addr)
		cliDev, _ := tunPair(t, "dsopc")
		cli, err := DialTCP(relay.addr(), cliDev, ka, false, true, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		assertDecoysFirst(t, cli, relay)
	})
}
