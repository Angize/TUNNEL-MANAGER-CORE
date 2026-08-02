//go:build linux

// L2 packet injection: send fully hand-crafted IPv4 packets to a peer via an AF_PACKET SOCK_RAW socket,
// so the kernel does NOT touch the L3 header. An IP_HDRINCL raw socket ALWAYS recomputes the IPv4 header
// checksum, which silently repairs a deliberately-bad one; AF_PACKET hands the frame to the driver
// verbatim. The Ethernet header comes from the kernel's own routing + neighbour tables, resolved lazily.
package packet

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// l2route is the Ethernet framing for reaching the peer: the egress interface and the
// source (our NIC) + destination (next-hop) MACs.
type l2route struct {
	ifindex int
	src     [6]byte
	dst     [6]byte
}

// l2inject injects raw IPv4 packets over AF_PACKET. The DESTINATION is supplied per send, not frozen at
// construction: a rotating destination pool would otherwise keep injecting every decoy over the FIRST
// destination's next hop, the decoy's IPv4 header carrying the new destination while the Ethernet frame
// went to the old gateway. mu also serializes sendTo against close so Sendto never hits a reused fd.
type l2inject struct {
	mu   sync.Mutex
	fd   int
	peer net.IP   // the destination rt was resolved FOR (nil until the first successful resolve)
	rt   *l2route // cached route for peer; nil forces a re-resolve
	// resolve overrides the route resolver in tests (nil => resolveL2, the real /proc + netlink one).
	resolve func(net.IP) (*l2route, error)
}

// newL2Inject opens the AF_PACKET SOCK_RAW send socket. Protocol 0 means it receives nothing
// (we only transmit), so it never floods its RX queue. It needs CAP_NET_RAW, which the raw/
// flux carriers already hold. No peer: sendTo carries the destination.
func newL2Inject() (*l2inject, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}
	return &l2inject{fd: fd}, nil
}

// routeTo returns the cached Ethernet route for peer, resolving (and caching) it when the cache is
// empty or was resolved for a DIFFERENT destination. Caller holds l.mu.
func (l *l2inject) routeTo(peer net.IP) (*l2route, error) {
	if l.rt != nil && l.peer.Equal(peer) {
		return l.rt, nil // steady state: one IP compare per decoy, no syscall
	}
	resolve := l.resolve
	if resolve == nil {
		resolve = resolveL2
	}
	rt, err := resolve(peer)
	if err != nil {
		return nil, err
	}
	l.peer, l.rt = peer, rt
	return rt, nil
}

func (l *l2inject) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd >= 0 {
		syscall.Close(l.fd)
		l.fd = -1
	}
}

// sendTo injects one IPv4 packet toward peer, prepending the Ethernet header for peer's next hop. peer
// must be the destination the tunnel ROUTES to — on a spoof-dst link that is NOT the forged dst in the
// packet's own header, and an injected frame has to make the same choice or it leaves by a different
// first hop than the flow it is camouflaging. The route is cached and re-resolved after a failure.
func (l *l2inject) sendTo(peer net.IP, ipPkt []byte) error {
	p := peer.To4()
	if p == nil {
		return fmt.Errorf("l2: peer %v is not IPv4", peer)
	}
	// Hold the mutex across the whole send — including the Sendto syscall — so a concurrent
	// close() cannot close (and the kernel reuse) the fd mid-send. close() takes the same
	// mutex, so it waits for any in-flight send to finish; Sendto makes no callback into
	// l2inject, so there is no deadlock.
	l.mu.Lock()
	defer l.mu.Unlock()
	rt, err := l.routeTo(p)
	if err != nil {
		return err
	}
	if l.fd < 0 {
		return fmt.Errorf("l2: injector closed")
	}

	frame := make([]byte, 14+len(ipPkt))
	copy(frame[0:6], rt.dst[:])
	copy(frame[6:12], rt.src[:])
	binary.BigEndian.PutUint16(frame[12:14], ethPIP) // 0x0800 IPv4
	copy(frame[14:], ipPkt)

	sa := &syscall.SockaddrLinklayer{Ifindex: rt.ifindex, Halen: 6}
	copy(sa.Addr[:6], rt.dst[:])
	if err := syscall.Sendto(l.fd, frame, 0, sa); err != nil {
		// Invalidate the cached route so the next send re-resolves it: a next-hop change
		// (gateway MAC churn, route flap) surfaces here as a Sendto failure, and dropping the
		// stale l2route lets resolveL2 pick up the fresh ifindex/MAC instead of injecting to a
		// dead next hop for the life of the process.
		l.rt = nil
		return err
	}
	return nil
}

// resolveL2 finds the egress interface and next-hop MAC for peer from the kernel routing and
// neighbour tables. next hop = the route's gateway (off-subnet) or the peer itself (on-link).
func resolveL2(peer net.IP) (*l2route, error) {
	ifname, gw, err := routeFor(peer)
	if err != nil {
		return nil, err
	}
	nextHop := gw
	if nextHop == nil {
		nextHop = peer // on-link: the peer is its own next hop
	}
	dst, err := neighMAC(nextHop, ifname)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("l2: %s has no Ethernet MAC", ifname)
	}
	rt := &l2route{ifindex: iface.Index, dst: dst}
	copy(rt.src[:], iface.HardwareAddr)
	return rt, nil
}

// routeFor reads /proc/net/route and returns the egress interface and gateway for the
// longest-prefix route matching peer (gw is nil for an on-link route). The Destination/
// Gateway/Mask columns are the 32-bit address printed as native-endian hex, which matches
// reading peer with binary.LittleEndian on our little-endian targets.
func routeFor(peer net.IP) (ifname string, gw net.IP, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	p4 := binary.LittleEndian.Uint32(peer.To4())
	best := -1
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fld := strings.Fields(sc.Text())
		if len(fld) < 8 {
			continue
		}
		dest, e1 := strconv.ParseUint(fld[1], 16, 32)
		mask, e2 := strconv.ParseUint(fld[7], 16, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		m := uint32(mask)
		if p4&m != uint32(dest)&m {
			continue // this route does not cover the peer
		}
		if ones := bits.OnesCount32(m); ones > best {
			best = ones
			ifname = fld[0]
			if g, _ := strconv.ParseUint(fld[2], 16, 32); g != 0 {
				var b [4]byte
				binary.LittleEndian.PutUint32(b[:], uint32(g))
				gw = net.IP(b[:]).To4()
			} else {
				gw = nil
			}
		}
	}
	if best < 0 {
		return "", nil, fmt.Errorf("l2: no route to %s", peer)
	}
	return ifname, gw, nil
}

// neighMAC reads /proc/net/arp and returns the resolved MAC for ip on ifname. Incomplete
// entries (ATF_COM/0x2 flag clear) are skipped — a cold neighbour yields an error so the
// caller degrades that decoy rather than sending to a zero MAC.
func neighMAC(ip net.IP, ifname string) (mac [6]byte, err error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return mac, err
	}
	defer f.Close()
	want := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fld := strings.Fields(sc.Text()) // IP HWtype Flags HWaddr Mask Device
		if len(fld) < 6 || fld[0] != want {
			continue
		}
		if fld[5] != ifname { // a peer IP could appear on several devices
			continue
		}
		flags, _ := strconv.ParseUint(fld[2], 0, 32)
		if flags&0x2 == 0 { // ATF_COM: only a completed entry has a usable MAC
			continue
		}
		hw, e := net.ParseMAC(fld[3])
		if e != nil || len(hw) != 6 {
			continue
		}
		copy(mac[:], hw)
		return mac, nil
	}
	return mac, fmt.Errorf("l2: neighbour %s on %s not resolved", want, ifname)
}
