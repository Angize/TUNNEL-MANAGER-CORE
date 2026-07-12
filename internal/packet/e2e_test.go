package packet

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// TestUDPServerMultiIP drives a full tunnel against a pooled UDP server bound on TWO loopback IPs at the
// same port. The client dials the SECOND IP (not the first-bound), and the test asserts both that data
// flows each way AND that the server then replies FROM the exact IP the client dialed (source-correct
// for a NAT'd client), rather than the OS-default first socket.
func TestUDPServerMultiIP(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "srvm")
	cliDev, cliCtrl := tunPair(t, "clim")
	ka := 1 * time.Second
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
	srv, err := Listen([]string{a1, a2}, srvDev, ka, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Listen multi: %v", err)
	}
	if len(srv.srvConns) != 2 {
		t.Fatalf("want 2 server sockets, got %d", len(srv.srvConns))
	}
	cli, err := Dial(a2, cliDev, ka, false, true, psk, cipher, false, 0, 0) // dial the SECOND IP
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(300 * time.Millisecond)

	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}
	if ip := srv.replyConn.Load().LocalAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("server reply socket = %v, want 127.0.0.2 (the IP the client dialed)", ip)
	}
	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}
}

// TestTCPServerMultiIP drives a full tunnel against a pooled TCP server bound on TWO loopback IPs at
// the same port. The client dials the SECOND IP; the test asserts both listeners exist and that data
// flows each way over the connection the client established to that IP. (TCP reply-source is inherently
// correct — the accepted socket's local addr IS the dialed IP — so the multi-bind here is about the
// server accepting ONLY on its selected pool IPs rather than every host IP.)
func TestTCPServerMultiIP(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "tsrvm")
	cliDev, cliCtrl := tunPair(t, "tclim")
	ka := 1 * time.Second
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
	srv, err := ListenTCP([]string{a1, a2}, srvDev, ka, false, true, psk, cipher, false, "")
	if err != nil {
		t.Fatalf("ListenTCP multi: %v", err)
	}
	if len(srv.lns) != 2 {
		t.Fatalf("want 2 server listeners, got %d", len(srv.lns))
	}
	cli, err := DialTCP(a2, cliDev, ka, false, true, psk, cipher, false, "") // dial the SECOND IP
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(300 * time.Millisecond)

	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}
	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}
}

// TestUDPServerReplyConnAuthGated is the regression guard for the reply-socket hijack: once a NAT'd
// client is established on one pool IP, an UNAUTHENTICATED datagram to ANOTHER pool IP must NOT move the
// server's reply socket (which would send downstream from an IP the client's NAT never saw, blackholing
// it). It brings a tunnel up on 127.0.0.2, fires garbage at the 127.0.0.1 socket, and asserts the reply
// socket stays on .2 AND downstream data still reaches the client.
func TestUDPServerReplyConnAuthGated(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, srvCtrl := tunPair(t, "srvg")
	cliDev, cliCtrl := tunPair(t, "clig")
	ka := 1 * time.Second
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	a1, a2 := fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("127.0.0.2:%d", port)
	srv, err := Listen([]string{a1, a2}, srvDev, ka, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Listen multi: %v", err)
	}
	cli, err := Dial(a2, cliDev, ka, false, true, psk, cipher, false, 0, 0) // establish on .2
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(300 * time.Millisecond)

	// Bring the tunnel fully up so an authenticated frame has committed replyConn to .2.
	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}
	if ip := srv.replyConn.Load().LocalAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("precondition: reply socket = %v, want 127.0.0.2", ip)
	}

	// Fire an UNAUTHENTICATED datagram at the OTHER pool IP (.1). A pre-fix server would move replyConn
	// to the .1 socket here; the fix gates the move on authentication, so it must stay on .2.
	atk, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		atk.Write(bytes.Repeat([]byte{0xEE}, 64)) // garbage: opens under no session, parses as no init
	}
	atk.Close()
	time.Sleep(150 * time.Millisecond) // let the .1 read loop process the garbage

	if ip := srv.replyConn.Load().LocalAddr().(*net.UDPAddr).IP; !ip.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("reply socket hijacked to %v by an unauthenticated packet — want it pinned to 127.0.0.2", ip)
	}
	// Downstream must still flow (proving replyConn still egresses from the IP the client dialed).
	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client after garbage"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch after garbage: got %d bytes", len(got))
	}
}

// tunPair returns a Device backed by one end of a unix datagram socketpair and
// the control file for the other end: write to ctrl -> dev.Read returns it
// (a packet "leaving" the app), and dev.Write -> ctrl.Read (a packet delivered
// to the app). SOCK_DGRAM preserves the one-packet-per-read TUN semantics.
func tunPair(t *testing.T, name string) (*tun.Device, *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	dev := tun.FromFile(os.NewFile(uintptr(fds[0]), name+"-dev"), name)
	ctrl := os.NewFile(uintptr(fds[1]), name+"-ctrl")
	t.Cleanup(func() { dev.Close(); ctrl.Close() })
	return dev, ctrl
}

func freeUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func readWithTimeout(t *testing.T, ctrl *os.File, what string) []byte {
	t.Helper()
	type res struct {
		b []byte
		n int
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _ := ctrl.Read(buf)
		ch <- res{buf, n}
	}()
	select {
	case r := <-ch:
		if r.n <= 0 {
			t.Fatalf("%s: empty read", what)
		}
		return r.b[:r.n]
	case <-time.After(4 * time.Second):
		t.Fatalf("%s: timed out — packet never traversed the tunnel", what)
		return nil
	}
}

type carrier interface {
	Run() error
	Close() error
}

// runTunnel drives a full server<->client core tunnel over a real socket for the
// given transport/obfs, injecting a packet each way and asserting it arrives
// intact — exercising seal/open, counter nonce, anti-replay, peer learning, and
// (tcp) handshake, the paths a live node runs.
func runTunnel(t *testing.T, transport string, obfs bool) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	const cryptoOn = true // exercises the full ephemeral handshake + session keys
	srvDev, srvCtrl := tunPair(t, "srv")
	cliDev, cliCtrl := tunPair(t, "cli")
	ka := 1 * time.Second

	var srv, cli carrier
	var err error
	if transport == "tcp" {
		addr := freeTCPPort(t)
		srv, err = ListenTCP([]string{addr}, srvDev, ka, obfs, cryptoOn, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		cli, err = DialTCP(addr, cliDev, ka, obfs, cryptoOn, psk, cipher, false, "")
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
	} else {
		addr := freeUDPPort(t)
		srv, err = Listen([]string{addr}, srvDev, ka, obfs, cryptoOn, psk, cipher, false, 0, 0)
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		cli, err = Dial(addr, cliDev, ka, obfs, cryptoOn, psk, cipher, false, 0, 0)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
	}
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	time.Sleep(300 * time.Millisecond)

	pkt1 := bytes.Repeat([]byte{0xC1}, 200)
	if _, err := cliCtrl.Write(pkt1); err != nil {
		t.Fatalf("inject client->server: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server"); !bytes.Equal(got, pkt1) {
		t.Fatalf("client->server payload mismatch: got %d bytes", len(got))
	}

	pkt2 := bytes.Repeat([]byte{0x5A}, 500)
	if _, err := srvCtrl.Write(pkt2); err != nil {
		t.Fatalf("inject server->client: %v", err)
	}
	if got := readWithTimeout(t, cliCtrl, "server->client"); !bytes.Equal(got, pkt2) {
		t.Fatalf("server->client payload mismatch: got %d bytes", len(got))
	}

	pkt3 := bytes.Repeat([]byte{0x33}, 120)
	if _, err := cliCtrl.Write(pkt3); err != nil {
		t.Fatalf("inject client->server #2: %v", err)
	}
	if got := readWithTimeout(t, srvCtrl, "client->server #2"); !bytes.Equal(got, pkt3) {
		t.Fatalf("client->server #2 payload mismatch")
	}
}

func TestTunnelUDP(t *testing.T)     { runTunnel(t, "udp", false) }
func TestTunnelUDPObfs(t *testing.T) { runTunnel(t, "udp", true) }
func TestTunnelTCP(t *testing.T)     { runTunnel(t, "tcp", false) }
func TestTunnelTCPObfs(t *testing.T) { runTunnel(t, "tcp", true) }
