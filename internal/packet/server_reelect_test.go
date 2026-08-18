package packet

import (
	"bytes"
	"testing"
	"time"
)

func TestServerReelectsDownstreamAfterLiveConnDies(t *testing.T) {
	const psk = "server-reelect-downstream-psk-123"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "reelect")
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, time.Second, false, true, psk, cipher, "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(100 * time.Millisecond)

	a := dialWSClient(t, addr, psk, cipher)
	waitFor(t, 4*time.Second, "A published as downstream", func() bool { return srv.cur.Load() != nil })

	b := dialWSClient(t, addr, psk, cipher)
	d1 := bytes.Repeat([]byte{0x41}, 200)
	if _, err := srvCtrl.Write(d1); err != nil {
		t.Fatalf("inject downstream d1: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream on A"); typ != typeData || !bytes.Equal(pt, d1) {
		t.Fatalf("downstream must stay on A while B has only connected (typ=%d)", typ)
	}

	live := srv.cur.Load()
	a.conn.Close()
	waitFor(t, 4*time.Second, "the server re-elected a downstream carrier after the live one died", func() bool {
		c := srv.cur.Load()
		return c != nil && c != live
	})

	d2 := bytes.Repeat([]byte{0x42}, 210)
	if _, err := srvCtrl.Write(d2); err != nil {
		t.Fatalf("inject downstream d2: %v", err)
	}
	if typ, pt := readFrameT(t, b, "downstream re-elected onto B"); typ != typeData || !bytes.Equal(pt, d2) {
		t.Fatalf("server dropped the download after the live carrier died (typ=%d)", typ)
	}

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
