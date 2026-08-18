package packet

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: condition not met within %v", what, d)
}

func dialWSClient(t *testing.T, addr, psk, cipher string) *connFramer {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r, err := wsClientHandshake(raw, "front.example", "/", time.Now().Add(5*time.Second))
	if err != nil {
		raw.Close()
		t.Fatalf("ws upgrade: %v", err)
	}
	wc := &wsConn{Conn: raw, r: r, client: true}
	cb := &TCP{cryptoOn: true, cipher: cipher, psk: psk}
	cf := cb.newFramer(wc)
	wc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := cb.clientHandshake(cf); err != nil {
		raw.Close()
		t.Fatalf("client handshake: %v", err)
	}
	wc.SetReadDeadline(time.Time{})
	if err := cf.writeFrame(typePing, nil); err != nil {
		raw.Close()
		t.Fatalf("prime ping: %v", err)
	}
	cf.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if typ, _, _, _, err := cf.readFrame(); err != nil || typ != typePong {
		raw.Close()
		t.Fatalf("prime pong: typ=%d err=%v", typ, err)
	}
	t.Cleanup(func() { raw.Close() })
	return cf
}

func readFrameT(t *testing.T, cf *connFramer, what string) (byte, []byte) {
	t.Helper()
	cf.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	typ, _, _, pt, err := cf.readFrame()
	if err != nil {
		t.Fatalf("%s: readFrame: %v", what, err)
	}
	return typ, append([]byte(nil), pt...)
}

func TestServerDownstreamFollowsData(t *testing.T) {
	const psk = "downstream-follows-data-psk-123456"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "sdf")
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

	pA := bytes.Repeat([]byte{0x11}, 150)
	if err := a.writeFrame(typeData, pA); err != nil {
		t.Fatalf("A data: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "A->server data"); !bytes.Equal(got, pA) {
		t.Fatalf("A->server payload mismatch")
	}
	d1 := bytes.Repeat([]byte{0x21}, 250)
	if _, err := srvCtrl.Write(d1); err != nil {
		t.Fatalf("inject downstream d1: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream on A"); typ != typeData || !bytes.Equal(pt, d1) {
		t.Fatalf("downstream d1 not delivered on A (typ=%d)", typ)
	}

	b := dialWSClient(t, addr, psk, cipher)
	d2 := bytes.Repeat([]byte{0x22}, 260)
	if _, err := srvCtrl.Write(d2); err != nil {
		t.Fatalf("inject downstream d2: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream stays on A after B connects"); typ != typeData || !bytes.Equal(pt, d2) {
		t.Fatalf("downstream must stay on A when B only connected (typ=%d)", typ)
	}

	if err := b.writeFrame(typePing, nil); err != nil {
		t.Fatalf("B ping: %v", err)
	}
	if typ, _ := readFrameT(t, b, "B pong"); typ != typePong {
		t.Fatalf("B ping should be answered by a pong, got typ=%d", typ)
	}
	d3 := bytes.Repeat([]byte{0x23}, 270)
	if _, err := srvCtrl.Write(d3); err != nil {
		t.Fatalf("inject downstream d3: %v", err)
	}
	if typ, pt := readFrameT(t, a, "downstream stays on A after B ping"); typ != typeData || !bytes.Equal(pt, d3) {
		t.Fatalf("a ping must not steal downstream (typ=%d)", typ)
	}

	pB := bytes.Repeat([]byte{0x31}, 160)
	if err := b.writeFrame(typeData, pB); err != nil {
		t.Fatalf("B data: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "B->server data"); !bytes.Equal(got, pB) {
		t.Fatalf("B->server payload mismatch")
	}
	d4 := bytes.Repeat([]byte{0x24}, 280)
	if _, err := srvCtrl.Write(d4); err != nil {
		t.Fatalf("inject downstream d4: %v", err)
	}
	if typ, pt := readFrameT(t, b, "downstream flipped to B"); typ != typeData || !bytes.Equal(pt, d4) {
		t.Fatalf("downstream must follow B's data (typ=%d)", typ)
	}

	a.conn.Close()
	time.Sleep(150 * time.Millisecond)
	d5 := bytes.Repeat([]byte{0x25}, 290)
	if _, err := srvCtrl.Write(d5); err != nil {
		t.Fatalf("inject downstream d5: %v", err)
	}
	if typ, pt := readFrameT(t, b, "delivery continues on B after A closes"); typ != typeData || !bytes.Equal(pt, d5) {
		t.Fatalf("closing A must not disturb B (typ=%d)", typ)
	}
}

func poolActive(p *wsPool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

func TestPinReleasesOnLanding(t *testing.T) {
	const psk = "ws-pin-release-psk-abcdefghijklmn"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "wprsrv")
	cliDev, _ := tunPair(t, "wprcli")
	ka := time.Second
	addr := freeTCPPort(t)
	srv, err := ListenWS(addr, srvDev, ka, false, true, psk, cipher, "")
	if err != nil {
		t.Fatalf("ListenWS: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	pool := newWSPool([]string{addr}, snis("front-a", "front-b"), "")
	cli := &TCP{dev: cliDev, cryptoOn: true, cipher: cipher, keepalive: ka, psk: psk,
		ws: true, wsTLS: false, pool: pool,
		idle: deadWindow(ka), isClient: true, addr: "pool", closeCh: make(chan struct{})}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	waitFor(t, 5*time.Second, "active up", func() bool { return cli.cur.Load() != nil })

	target := "front-b"
	if poolActive(pool) == addr+" · front-b" {
		target = "front-a"
	}
	cli.SelectEdge("sni", target)

	waitFor(t, 5*time.Second, "pin released on landing", func() bool {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		return pool.pinSNI == "" && pool.active == addr+" · "+target
	})
}
