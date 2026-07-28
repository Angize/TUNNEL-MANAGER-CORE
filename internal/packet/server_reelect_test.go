package packet

import (
	"bytes"
	"testing"
	"time"
)

// TestServerReelectsDownstreamAfterLiveConnDies drives the real server: two authenticated carriers,
// the live one dies, and the client sends NOTHING afterwards.
//
// The downstream target follows the client's DATA frames (handleFrame) and nothing else — ping and
// pong deliberately do not move it, and publishServerConn only ever claims an EMPTY slot, so a
// second connection never steals downstream just by connecting. That left one hole: when the live
// connection died while another authenticated one was up (a warm standby, or the parked carrier of a
// destination rotation), onConnErr cleared b.cur and NO path re-elected. Every server->client packet
// was then dropped until the client happened to send a DATA frame. Inside the tunnel a TCP flow heals
// in milliseconds off its own ACKs; a one-way download — UDP video, a file the client is only
// receiving — stayed completely dark for as long as the client had nothing to send.
//
// The test is deliberately silent on B: it never writes a frame on it after the failure, so a green
// result can only come from the server re-electing on its own.
func TestServerReelectsDownstreamAfterLiveConnDies(t *testing.T) {
	const psk = "server-reelect-downstream-psk-123"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "reelect")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, time.Second, false, true, psk, cipher)
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(100 * time.Millisecond) // let the listener come up

	// A connects first and becomes the downstream target (CAS on an empty slot).
	a := dialWSClient(t, addr, psk, cipher)
	waitFor(t, 4*time.Second, "A published as downstream", func() bool { return srv.cur.Load() != nil })

	// B connects and authenticates — the warm standby. It must NOT steal downstream by connecting,
	// which is the invariant the re-election has to respect.
	b := dialWSClient(t, addr, psk, cipher)
	d1 := bytes.Repeat([]byte{0x41}, 200)
	if _, err := srvCtrl.Write(d1); err != nil {
		t.Fatalf("inject downstream d1: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream on A"); typ != typeData || !bytes.Equal(pt, d1) {
		t.Fatalf("downstream must stay on A while B has only connected (typ=%d)", typ)
	}

	// The live carrier dies. From here on the client writes NOTHING: this is the one-way download.
	live := srv.cur.Load()
	a.conn.Close()
	waitFor(t, 4*time.Second, "the server re-elected a downstream carrier after the live one died", func() bool {
		c := srv.cur.Load()
		return c != nil && c != live
	})

	// The download keeps flowing, on B, with no upstream traffic to trigger it.
	d2 := bytes.Repeat([]byte{0x42}, 210)
	if _, err := srvCtrl.Write(d2); err != nil {
		t.Fatalf("inject downstream d2: %v", err)
	}
	if typ, pt := readFrameT(t, b, "downstream re-elected onto B"); typ != typeData || !bytes.Equal(pt, d2) {
		t.Fatalf("server dropped the download after the live carrier died (typ=%d)", typ)
	}

	// And the client's own choice still wins over the re-election: DATA on B keeps it there, and the
	// re-elected carrier is a normal downstream target, not a special case.
	pB := bytes.Repeat([]byte{0x43}, 160)
	if err := b.writeFrame(typeData, pB); err != nil {
		t.Fatalf("B data: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "B->server data"); !bytes.Equal(got, pB) {
		t.Fatalf("B->server payload mismatch")
	}
	d3 := bytes.Repeat([]byte{0x44}, 220)
	if _, err := srvCtrl.Write(d3); err != nil {
		t.Fatalf("inject downstream d3: %v", err)
	}
	if typ, pt := readFrameT(t, b, "downstream stays on B"); typ != typeData || !bytes.Equal(pt, d3) {
		t.Fatalf("downstream left B after B sent data (typ=%d)", typ)
	}
}
