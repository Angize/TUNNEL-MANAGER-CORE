package packet

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const probePSK = "probe-shared-pre-shared-key-1234567890"

// probePair brings up a REAL udp client/server pair bound on two loopback IPs at one port, with a
// destination rotation pool on the client (a1, a2, then any extra entries). The client dials a1, so
// everything past it is an endpoint the live carrier is not on. It returns only once the peer has
// answered, so a test that then asserts something about a live tunnel really has one.
func probePair(t *testing.T, ka time.Duration, tag string, extra ...string) (cli, srv *UDP, a1, a2 string, cliCtrl, srvCtrl *os.File) {
	t.Helper()
	srvDev, sc := tunPair(t, tag+"s")
	cliDev, cc := tunPair(t, tag+"c")
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1 = fmt.Sprintf("127.0.0.1:%d", port)
	a2 = fmt.Sprintf("127.0.0.2:%d", port)
	srv, err = Listen([]string{a1, a2}, srvDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err = Dial(a1, cliDev, ka, false, true, probePSK, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dir := t.TempDir()
	cli.SetStatusPath(filepath.Join(dir, "core.json"))
	cli.SetPeerPool(NewPeerPool(append([]string{a1, a2}, extra...), 0, filepath.Join(dir, "pool.json")))
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	pkt := bytes.Repeat([]byte{0xC7}, 120)
	deadline := time.Now().Add(10 * time.Second)
	for !cli.peerAnswered.Load() {
		if _, err := cc.Write(pkt); err != nil {
			t.Fatalf("inject: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cli, srv, a1, a2, cc, sc
}
