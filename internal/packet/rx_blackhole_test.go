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

// rxBlackhole is a transparent TCP relay that can silently stop delivering the SERVER->CLIENT
// direction while leaving both sockets open and the CLIENT->SERVER direction untouched. That is
// exactly what a receive-direction blackhole looks like from the client: no FIN, no RST, nothing the
// kernel can report — the carrier stays writable forever, and only the ABSENCE of answers can reveal
// it. Closing a socket instead would test a completely different (and already-handled) failure.
type rxBlackhole struct {
	ln   net.Listener
	down atomic.Bool // true = drop everything coming back from the server
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
	go func() { // upstream always flows, so the peer keeps receiving and keeps answering
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

// TestReceiveBlackholeIsDetectedWhileOutboundDataFlows guards the worst kind of stuck tunnel: the
// RECEIVE direction dies, the panel dot goes red, and the core does nothing about it — no reconnect,
// no failover, not one log line, forever.
//
// A TCP-family carrier has exactly TWO dead-detection paths, and a successful outbound write used to
// hold BOTH of them open: tunLoop stamped the (then direction-agnostic) data timestamp that
// b.lastRxData replaced on every write, which made recentData() true and
// suppressed the keepalive ping (so no ping could go unanswered), and it pushed the read deadline
// forward (so the idle reaper could not fire either). "Outbound data keeps flowing" is not a contrived
// state — the inner TCP retransmits into a blackhole, so it is the NORMAL consequence of the failure.
//
// The test therefore keeps writing into the client's TUN for the whole window and asserts the client
// drops the carrier anyway. b.idle is 60s here (idleMinSecs floors it well above 4×keepalive), so the
// idle reaper cannot be what rescues this inside the assert window: ping-loss is the only mechanism
// that can make it pass, which is exactly the mechanism outbound data used to disable.
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

	bh.down.Store(true) // the receive direction dies; both sockets stay open and writable

	// Keep real DATA moving OUTBOUND for the whole window, faster than one keepalive period — this is
	// the traffic that used to convince the client everything was fine.
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
