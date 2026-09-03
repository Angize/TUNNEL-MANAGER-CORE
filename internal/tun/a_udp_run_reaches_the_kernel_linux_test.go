//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"
)

func udpPkt(t *testing.T, dst net.IP, sport, dport uint16, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+udpHdrLen+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], 0x4321)
	pkt[6] = 0x40
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 91, 0, 2})
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[20:22], sport)
	binary.BigEndian.PutUint16(pkt[22:24], dport)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdrLen+len(payload)))
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[26:28], l4Checksum(pkt, 20, false, 17))
	return pkt
}

func realTun(t *testing.T, name, addr string) *Device {
	t.Helper()
	devs, err := OpenN(name, 1500, addr, true, 1)
	if err != nil {
		t.Skipf("no real tun here (needs root and /dev/net/tun): %v", err)
	}
	t.Cleanup(func() {
		for _, d := range devs {
			d.Close()
		}
		exec.Command("ip", "link", "del", devs[0].Name).Run()
	})
	return devs[0]
}

// The unit tests below build the super-packet and read the bytes back off a socketpair, which proves
// the header is what this code MEANT to write. Only the kernel can say whether it is what the kernel
// expects: a wrong gso_size, hdr_len or csum_offset is accepted by the write and then either dropped
// or delivered as garbage, with no error anywhere. So this drives a real tun and counts what actually
// comes out the other side of the stack.
func TestAUDPRunIsSegmentedByTheKernelIntoTheDatagramsItCameFrom(t *testing.T) {
	dev := realTun(t, "usot0", "10.91.0.1/24")
	if !dev.uso {
		t.Skip("this kernel did not grant TUN_F_USO4/USO6, so there is no udp offload to test")
	}
	ip := net.IPv4(10, 91, 0, 1)
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 9911})
	if err != nil {
		t.Fatalf("listening on the tun address: %v", err)
	}
	defer sock.Close()

	for _, tc := range []struct {
		name  string
		sizes []int
	}{
		{"five equal segments", []int{600, 600, 600, 600, 600}},
		{"a short last segment", []int{600, 600, 600, 137}},
		{"the smallest run there is", []int{40, 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pkts [][]byte
			var want []string
			for i, n := range tc.sizes {
				pay := make([]byte, n)
				for j := range pay {
					pay[j] = byte(i*7 + j)
				}
				pkts = append(pkts, udpPkt(t, ip, 5000, 9911, pay))
				want = append(want, fmt.Sprintf("%d:%d:%d", n, pay[0], pay[len(pay)-1]))
			}
			before := dev.nWrites.Load()
			if err := dev.WriteBatch(pkts); err != nil {
				t.Fatalf("WriteBatch: %v", err)
			}
			if got := dev.nWrites.Load() - before; got != 1 {
				t.Fatalf("%d super-packet writes, want exactly 1 -- the run was not coalesced at all", got)
			}

			var seen []string
			buf := make([]byte, 65535)
			sock.SetReadDeadline(time.Now().Add(3 * time.Second))
			for range tc.sizes {
				n, _, err := sock.ReadFrom(buf)
				if err != nil {
					t.Fatalf("after %d of %d datagrams: %v -- the kernel took the super-packet and "+
						"then dropped it, which is what a wrong gso_size or csum_offset looks like",
						len(seen), len(tc.sizes), err)
				}
				seen = append(seen, fmt.Sprintf("%d:%d:%d", n, buf[0], buf[n-1]))
			}
			for i := range want {
				if seen[i] != want[i] {
					t.Fatalf("datagram %d came out as %s, want %s (len:first:last)", i, seen[i], want[i])
				}
			}
			sock.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			if n, _, err := sock.ReadFrom(buf); err == nil {
				t.Fatalf("a %d-byte extra datagram arrived: the kernel cut the super-packet into more "+
					"pieces than it was built from", n)
			}
		})
	}
}

// Two flows interleaved must not be welded together: every segment of one super-packet is delivered
// with the lead packet's header, so a coalesced pair from different ports would arrive on the wrong
// socket entirely.
func TestTwoUDPFlowsAreNotWeldedIntoOneSuperPacket(t *testing.T) {
	dev := realTun(t, "usot1", "10.92.0.1/24")
	if !dev.uso {
		t.Skip("this kernel did not grant TUN_F_USO4/USO6")
	}
	ip := net.IPv4(10, 92, 0, 1)
	a, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 9921})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 9922})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	pay := make([]byte, 300)
	pkts := [][]byte{
		udpPkt(t, ip, 5000, 9921, pay),
		udpPkt(t, ip, 5000, 9922, pay),
		udpPkt(t, ip, 5000, 9921, pay),
	}
	if err := dev.WriteBatch(pkts); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	buf := make([]byte, 65535)
	for _, s := range []struct {
		port int
		conn *net.UDPConn
		want int
	}{{9921, a, 2}, {9922, b, 1}} {
		got := 0
		for {
			s.conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			n, _, err := s.conn.ReadFrom(buf)
			if err != nil {
				break
			}
			if n != len(pay) {
				t.Fatalf("port %d got a %d-byte datagram, want %d", s.port, n, len(pay))
			}
			got++
		}
		if got != s.want {
			t.Fatalf("port %d received %d datagrams, want %d -- the two flows were coalesced together",
				s.port, got, s.want)
		}
	}
}
