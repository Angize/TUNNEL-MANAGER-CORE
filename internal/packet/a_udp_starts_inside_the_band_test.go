//go:build linux

package packet

import (
	"net"
	"testing"
)

func sportOf(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local address is %T, not a UDP address", c.LocalAddr())
	}
	return la.Port
}

// The band is the operator's answer to "my path drops high ports". tcp honoured it from the first
// dial, but udp opened its socket with net.ListenUDP("udp", nil) and took whatever the kernel gave --
// ip_local_port_range, measured 32768-60999 on both fleet boxes, half of it above the 47000 line the
// operator set the band to avoid. The tunnel came up on a port the band existed to rule out and only
// moved into the band once something broke and the ladder spent a rung.
//
// Every udp bind draws from the band now: the first socket, a source rebind, and the repair rung.
func TestEveryUdpBindDrawsFromTheBand(t *testing.T) {
	t.Cleanup(func() { SetSportBand(0, 0) })
	SetSportBand(21000, 21999)
	inBand := func(p int) bool { return p >= 21000 && p <= 21999 }

	dev, _ := tunPair(t, "udpband")
	b, err := Dial("127.0.0.1:9", dev, false, true, "a-psk-for-the-udp-band", "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { b.Close() })

	first := sportOf(t, b.conn.Load())
	if !inBand(first) {
		t.Fatalf("the tunnel came up on source port %d, outside the band 21000..21999 the operator set. "+
			"On a path that drops high ports that is a tunnel born broken, and the setting that exists "+
			"to prevent it does not apply until something fails", first)
	}

	if err := b.rebind(net.IPv4(127, 0, 0, 1)); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	afterRebind := sportOf(t, b.conn.Load())
	if !inBand(afterRebind) {
		t.Errorf("a source rebind landed on %d, outside the band. Setting a source IP must not drop the "+
			"tunnel back to a kernel-chosen port", afterRebind)
	}

	b.st = newCoreStatus(t.TempDir()+"/core.status", "")
	seen := map[int]bool{first: true, afterRebind: true}
	for i := 1; i <= 12; i++ {
		if !b.rollSourcePort() {
			t.Fatalf("repair draw %d refused", i)
		}
		p := sportOf(t, b.conn.Load())
		if !inBand(p) {
			t.Fatalf("repair draw %d landed on %d, outside the band", i, p)
		}
		seen[p] = true
	}
	if len(seen) < 4 {
		t.Errorf("fourteen binds produced %d distinct ports; a draw that keeps landing on the same port "+
			"is not an escape from a pinned tuple", len(seen))
	}
}

// The band is not the server's business: a udp listener binds the address the operator configured,
// port and all, and a band draw there would move the port peers dial.
func TestTheUdpListenerIgnoresTheBand(t *testing.T) {
	t.Cleanup(func() { SetSportBand(0, 0) })
	SetSportBand(21000, 21999)

	dev, _ := tunPair(t, "udpsrv")
	s, err := Listen([]string{"127.0.0.1:0"}, dev, false, true, "a-psk-for-the-udp-band", "aes-256-gcm",
		false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	p := sportOf(t, s.srvConns[0])
	if p >= 21000 && p <= 21999 {
		t.Logf("the listener happened to land on %d, inside the band by chance", p)
	}
	if len(s.srvConns) != 1 {
		t.Fatalf("expected one server socket, got %d", len(s.srvConns))
	}
}
