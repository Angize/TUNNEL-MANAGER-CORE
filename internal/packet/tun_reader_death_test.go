//go:build linux

package packet

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

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
		time.Sleep(200 * time.Millisecond)

		syscall.Shutdown(devFd, syscall.SHUT_RD)

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
		syscall.Shutdown(cliFd, syscall.SHUT_RD)

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("Run returned nil after the TUN reader died — main reads that as a clean stop, so nothing restarts")
			}
			t.Logf("Run returned as it should: %v", err)
		case <-time.After(5 * time.Second):

			if hb := cli.lastRx.Load(); hb > hbBefore {
				t.Fatalf("the TUN reader died, Run never returned, and the heartbeat ADVANCED anyway "+
					"(%d -> %d): this is the green dot on a tunnel carrying nothing", hbBefore, hb)
			}
			t.Fatal("the TUN reader died and Run never returned — nothing can restart the carrier")
		}
	})
}
