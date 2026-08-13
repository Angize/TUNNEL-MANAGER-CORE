//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runBPF is a classic-BPF interpreter for exactly the instructions these filters use, so a test can
// see what the KERNEL will keep rather than compare instruction words to a golden copy. Anything else
// is a failure, which is the point: a filter grown past this is a filter nobody here has read.
func runBPF(t *testing.T, prog []unix.SockFilter, pkt []byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_B | unix.BPF_ABS:
			if int(in.K) >= len(pkt) {
				return 0 // out of bounds: the kernel drops the packet
			}
			a = uint32(pkt[in.K])
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if int(in.K)+4 > len(pkt) {
				return 0
			}
			a = binary.BigEndian.Uint32(pkt[in.K : in.K+4])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("the filter uses instruction %#x, which this interpreter does not model", in.Code)
		}
	}
	t.Fatal("the filter ran off the end without returning")
	return 0
}

// ip4 builds the head of an IPv4 packet as AF_PACKET SOCK_DGRAM delivers it: no link header, so
// offset 0 is the IP header.
func ip4(proto int, src, dst string) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = byte(proto)
	copy(p[12:16], net.ParseIP(src).To4())
	copy(p[16:20], net.ParseIP(dst).To4())
	return p
}

// Every AF_PACKET socket the carriers open is handed a copy of EVERY IPv4 frame on the host, and both
// receive loops then drop nearly all of it in Go — a copy into userspace and a wake-up per packet of
// somebody else's traffic. The filters must select exactly what those loops keep: no more (wasted) and
// no less (a frame the tunnel needs, dropped by the kernel before anything can see it).
func TestTheSocketFiltersKeepExactlyWhatTheReceiveLoopsWant(t *testing.T) {
	const decoy, other = "198.51.100.9", "198.51.100.10"

	t.Run("flux keeps udp and nothing else", func(t *testing.T) {
		prog := bpfIPProto(protoUDP)
		for _, tc := range []struct {
			name string
			pkt  []byte
			keep bool
		}{
			{"a udp carrier frame", ip4(protoUDP, "203.0.113.1", "10.0.0.1"), true},
			{"the host's tcp traffic", ip4(6, "203.0.113.1", "10.0.0.1"), false},
			{"an icmp echo", ip4(1, "203.0.113.1", "10.0.0.1"), false},
			{"a bare raw-IP frame", ip4(253, "203.0.113.1", "10.0.0.1"), false},
		} {
			got := runBPF(t, prog, tc.pkt) > 0
			if got != tc.keep {
				t.Errorf("%s: kept=%v, want %v", tc.name, got, tc.keep)
			}
		}
	})

	t.Run("a decoy server keeps its own protocol at its own destination", func(t *testing.T) {
		prog := bpfIPProtoDst(253, net.ParseIP(decoy))
		for _, tc := range []struct {
			name string
			pkt  []byte
			keep bool
		}{
			{"a carrier frame aimed at the decoy", ip4(253, "203.0.113.1", decoy), true},
			{"the same protocol to somebody else", ip4(253, "203.0.113.1", other), false},
			{"another protocol to the decoy", ip4(17, "203.0.113.1", decoy), false},
			{"unrelated host traffic", ip4(6, "203.0.113.1", other), false},
		} {
			got := runBPF(t, prog, tc.pkt) > 0
			if got != tc.keep {
				t.Errorf("%s: kept=%v, want %v", tc.name, got, tc.keep)
			}
		}
	})

	t.Run("the probe socket keeps nothing", func(t *testing.T) {
		if runBPF(t, bpfDropAll(), ip4(protoUDP, "203.0.113.1", "10.0.0.1")) != 0 {
			t.Error("the capability probe's socket would queue traffic nobody ever reads")
		}
	})

	// A whole frame, not a truncated one: a filter that returns a short length silently cuts every
	// packet the tunnel receives, which the Go side would then decode as garbage.
	if n := runBPF(t, bpfIPProto(protoUDP), ip4(protoUDP, "203.0.113.1", "10.0.0.1")); n < 65535 {
		t.Errorf("the accept length is %d — frames would be truncated to that", n)
	}

	// ...and the kernel has to accept the programs. Attaching to a plain UDP socket runs the same
	// verifier as an AF_PACKET one and needs no privileges, so this holds everywhere the tests do.
	for name, prog := range map[string][]unix.SockFilter{
		"flux":  bpfIPProto(protoUDP),
		"decoy": bpfIPProtoDst(253, net.ParseIP(decoy)),
		"drop":  bpfDropAll(),
	} {
		if err := attachTo(t, prog); err != nil {
			t.Errorf("the kernel refused the %s filter: %v", name, err)
		}
	}
}

func attachTo(t *testing.T, prog []unix.SockFilter) error {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]})
}

// ...and then the kernel really has to drop them. This one opens the socket the carrier opens, with
// the filter the carrier attaches, and looks at what actually turns up: the box's own ssh session is a
// steady stream of TCP, so "no TCP arrived" is a live negative control rather than an assumption.
func TestTheFluxFilterDropsEverythingButUDPInTheKernel(t *testing.T) {
	fd, err := openAfpacket(bpfIPProto(protoUDP), "test")
	if err != nil {
		t.Skipf("AF_PACKET needs CAP_NET_RAW; not measuring the kernel here: %v", err)
	}
	defer syscall.Close(fd)

	// One UDP datagram of our own, so the count below is not waiting on the box being busy.
	c, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		_, _ = c.Write([]byte("filter-probe"))
	}
	_ = c.Close()

	buf := make([]byte, 2048)
	seen := map[byte]int{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			t.Fatalf("recvfrom: %v", err)
		}
		if n < 20 {
			continue
		}
		seen[buf[9]]++
		if seen[protoUDP] > 0 && time.Now().After(deadline.Add(-2*time.Second)) {
			break // we have what we came for; do not sit here for the whole window
		}
	}
	if seen[protoUDP] == 0 {
		t.Errorf("the filter dropped our own UDP datagrams as well: saw %v", seen)
	}
	for proto, n := range seen {
		if proto != protoUDP {
			t.Errorf("protocol %d reached userspace %d time(s) despite the filter: %v", proto, n, seen)
		}
	}
}
