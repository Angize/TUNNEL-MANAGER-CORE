//go:build linux

package packet

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// tunPairFD is tunPair with the DEVICE end's raw fd exposed, so a test can make the carrier's blocked
// TUN read fail. Nothing else can, measured on the box rather than assumed: syscall.Socketpair hands
// back BLOCKING fds, so os.NewFile cannot make them pollable and closing the Device does not interrupt
// a read already parked in the kernel; and on an AF_UNIX SOCK_DGRAM pair closing the PEER does not wake
// the reader either. shutdown(SHUT_RD) does — it returns EOF immediately.
func tunPairFD(t *testing.T, name string) (*tun.Device, *os.File, int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	dev := tun.FromFile(os.NewFile(uintptr(fds[0]), name+"-dev"), name)
	ctrl := os.NewFile(uintptr(fds[1]), name+"-ctrl")
	t.Cleanup(func() { dev.Close(); ctrl.Close() })
	return dev, ctrl, fds[0]
}

// TestTunReaderDeathStopsTheCarrier guards against the worst failure this carrier has: a green dot on
// a tunnel that cannot move a single byte.
//
// tunLoop is the ONLY reader of the TUN device. It used to be started as a fire-and-forget
// `go b.tunLoop()`, so when the device died the reader returned and nothing noticed: on the client the
// keepalive loop kept pinging, the pongs kept stamping b.lastRx, and the heartbeat the panel reads
// stayed fresh — a tunnel reported healthy with 100% of the traffic on the floor, and no event, no
// reconnect and no restart to break out of it. udp/raw/flux hand this error back from Run; main logs
// it and the process exits, and systemd restarts onto a fresh device.
//
// The assertion is exactly that: Run RETURNS, with an error. That is what turns a permanently dead
// tunnel into a restart. Both roles run tunLoop, so both are covered.
func TestTunReaderDeathStopsTheCarrier(t *testing.T) {
	const psk = "tun-reader-death-psk-abcdefghijkl"
	const cipher = "aes-256-gcm"

	t.Run("server", func(t *testing.T) {
		dev, _, devFd := tunPairFD(t, "a2srv")
		addr := freeTCPPort(t)
		srv, err := ListenTCP([]string{addr}, dev, time.Second, false, true, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		t.Cleanup(func() { srv.Close() })
		done := make(chan error, 1)
		go func() { done <- srv.Run() }()
		time.Sleep(200 * time.Millisecond) // let the loops start and park in their reads

		syscall.Shutdown(devFd, syscall.SHUT_RD) // the TUN dies — NOT a shutdown; srv.Close was never called

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("Run returned nil after the TUN reader died — main reads that as a clean stop, so nothing restarts")
			}
			t.Logf("Run returned as it should: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("the TUN reader died and Run never returned: the carrier stays 'up' forever with no way " +
				"to move a packet, and the panel keeps reading it green")
		}
	})

	t.Run("client", func(t *testing.T) {
		// A real server to dial, so the client is fully established — keepalives running, heartbeat
		// advancing — which is the state that made this invisible in the first place.
		srvDev, _ := tunPair(t, "a2csrv")
		addr := freeTCPPort(t)
		srv, err := ListenTCP([]string{addr}, srvDev, time.Second, false, true, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		go srv.Run()
		t.Cleanup(func() { srv.Close() })

		cliDev, _, cliFd := tunPairFD(t, "a2cli")
		cli, err := DialTCP(addr, cliDev, time.Second, false, true, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		t.Cleanup(func() { cli.Close() })
		done := make(chan error, 1)
		go func() { done <- cli.Run() }()
		waitFor(t, 5*time.Second, "the client tunnel came up", func() bool { return cli.cur.Load() != nil })

		hbBefore := cli.lastRx.Load()
		syscall.Shutdown(cliFd, syscall.SHUT_RD) // the client's TUN dies

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("Run returned nil after the TUN reader died — main reads that as a clean stop, so nothing restarts")
			}
			t.Logf("Run returned as it should: %v", err)
		case <-time.After(5 * time.Second):
			// Put the symptom itself in the failure message: the heartbeat kept moving on a dead tunnel.
			if hb := cli.lastRx.Load(); hb > hbBefore {
				t.Fatalf("the TUN reader died, Run never returned, and the heartbeat ADVANCED anyway "+
					"(%d -> %d): this is the green dot on a tunnel carrying nothing", hbBefore, hb)
			}
			t.Fatal("the TUN reader died and Run never returned — nothing can restart the carrier")
		}
	})
}
