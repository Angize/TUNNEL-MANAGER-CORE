package packet

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestUDPRotationKeepsStreamFlowing(t *testing.T) {
	const psk = "rot-stream-psk-abcdefghijklmnop"
	const cipher = "chacha20-poly1305"
	srvDev, srvCtrl := tunPair(t, "rsrvrot")
	cliDev, cliCtrl := tunPair(t, "rclirot")

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)

	srv, err := Listen([]string{a1, a2}, srvDev, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(a1, cliDev, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	cli.SetPeerPool(NewPeerPool([]string{a1, a2}, 700*time.Millisecond, ""))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(400 * time.Millisecond)

	stop := make(chan struct{})
	go func() {
		pkt := bytes.Repeat([]byte{0xB7}, 120)
		tk := time.NewTicker(30 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				_, _ = cliCtrl.Write(pkt)
			}
		}
	}()
	defer close(stop)

	var last time.Time
	var maxGap time.Duration
	buf := make([]byte, 2048)
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		_ = srvCtrl.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
		n, err := srvCtrl.Read(buf)
		now := time.Now()
		if err != nil {
			t.Fatalf("no packet for >1.2s — a rotation stalled the stream")
		}
		if n <= 0 {
			continue
		}
		if !last.IsZero() {
			if g := now.Sub(last); g > maxGap {
				maxGap = g
			}
		}
		last = now
	}
	_ = srvCtrl.SetReadDeadline(time.Time{})

	if maxGap > 500*time.Millisecond {
		t.Fatalf("largest stream gap across a rotation = %v, want < 500ms (rotation must not stall the stream)", maxGap)
	}
}

func TestUDPReHandshakeOnReconnect(t *testing.T) {
	const psk = "reconnect-psk-abcdefghijklmnop"
	const cipher = "chacha20-poly1305"
	srvDev, srvCtrl := tunPair(t, "rsrv")
	addr := freeUDPPort(t)
	srv, err := Listen([]string{addr}, srvDev, true, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	send := func(tag string) {
		cliDev, cliCtrl := tunPair(t, tag)
		cli, err := Dial(addr, cliDev, true, true, psk, cipher, false, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		go cli.Run()
		time.Sleep(300 * time.Millisecond)
		pkt := bytes.Repeat([]byte{0x77}, 180)
		if _, err := cliCtrl.Write(pkt); err != nil {
			t.Fatalf("%s inject: %v", tag, err)
		}
		if got := readWithTimeout(t, srvCtrl, tag); !bytes.Equal(got, pkt) {
			t.Fatalf("%s: payload did not traverse the tunnel", tag)
		}
		cli.Close()
		cliDev.Close()
		cliCtrl.Close()
		time.Sleep(100 * time.Millisecond)
	}

	send("cli-first")
	send("cli-second")
}
