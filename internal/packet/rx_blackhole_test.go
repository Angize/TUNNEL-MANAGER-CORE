package packet

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type rxBlackhole struct {
	ln   net.Listener
	down atomic.Bool
}

func newRxBlackhole(t *testing.T, target string) *rxBlackhole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen: %v", err)
	}
	bh := &rxBlackhole{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go bh.pipe(c, target)
		}
	}()
	return bh
}

func (bh *rxBlackhole) addr() string { return bh.ln.Addr().String() }

func (bh *rxBlackhole) pipe(cli net.Conn, target string) {
	srv, err := net.Dial("tcp", target)
	if err != nil {
		cli.Close()
		return
	}
	defer cli.Close()
	defer srv.Close()
	go func() {
		io.Copy(srv, cli)
		srv.Close()
		cli.Close()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := srv.Read(buf)
		if n > 0 && !bh.down.Load() {
			if _, werr := cli.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func TestReceiveBlackholeIsDetectedWhileOutboundDataFlows(t *testing.T) {
	const psk = "rx-blackhole-pre-shared-key-123456"
	const cipher = "aes-256-gcm"
	const ka = 150 * time.Millisecond

	srvDev, _ := tunPair(t, "bhsrv")
	srvAddr := freeTCPPort(t)
	srv, err := ListenTCP([]string{srvAddr}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	go srv.Run()
	t.Cleanup(func() { srv.Close() })

	bh := newRxBlackhole(t, srvAddr)

	cliDev, cliCtrl := tunPair(t, "bhcli")
	cli, err := DialTCP(bh.addr(), cliDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	go cli.Run()
	t.Cleanup(func() { cli.Close() })
	waitFor(t, 5*time.Second, "the client tunnel came up", func() bool { return cli.cur.Load() != nil })

	bh.down.Store(true)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt := bytes.Repeat([]byte{0x42}, 200)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := cliCtrl.Write(pkt); err != nil {
				return
			}
			time.Sleep(ka / 5)
		}
	}()
	defer func() { close(stop); wg.Wait() }()

	waitFor(t, 5*time.Second,
		"the client never noticed the receive blackhole: it kept writing data into a dead direction, "+
			"the keepalive ping stayed suppressed and the read deadline stayed pushed forward, so the "+
			"carrier was never dropped and nothing ever re-dialled or failed over",
		func() bool { return cli.cur.Load() == nil })
}
