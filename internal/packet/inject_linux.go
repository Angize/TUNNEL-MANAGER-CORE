//go:build linux

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

type l2route struct {
	ifindex int
	src     [6]byte
	dst     [6]byte
}

type l2inject struct {
	mu   sync.Mutex
	fd   int
	peer net.IP
	rt   *l2route

	resolve func(net.IP) (*l2route, error)
}

func newL2Inject() (*l2inject, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}
	return &l2inject{fd: fd}, nil
}

func (l *l2inject) routeTo(peer net.IP) (*l2route, error) {
	if l.rt != nil && l.peer.Equal(peer) {
		return l.rt, nil
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

func (l *l2inject) sendTo(peer net.IP, ipPkt []byte) error {
	p := peer.To4()
	if p == nil {
		return fmt.Errorf("l2: peer %v is not IPv4", peer)
	}

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
	binary.BigEndian.PutUint16(frame[12:14], ethPIP)
	copy(frame[14:], ipPkt)

	sa := &syscall.SockaddrLinklayer{Ifindex: rt.ifindex, Halen: 6}
	copy(sa.Addr[:6], rt.dst[:])
	if err := syscall.Sendto(l.fd, frame, 0, sa); err != nil {
		l.rt = nil
		return err
	}
	return nil
}

func resolveL2(peer net.IP) (*l2route, error) {
	ifname, gw, err := routeFor(peer)
	if err != nil {
		return nil, err
	}
	nextHop := gw
	if nextHop == nil {
		nextHop = peer
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

func routeFor(peer net.IP) (ifname string, gw net.IP, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	p4 := binary.LittleEndian.Uint32(peer.To4())
	best := -1
	sc := bufio.NewScanner(f)
	sc.Scan()
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
			continue
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

func neighMAC(ip net.IP, ifname string) (mac [6]byte, err error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return mac, err
	}
	defer f.Close()
	want := ip.String()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fld := strings.Fields(sc.Text())
		if len(fld) < 6 || fld[0] != want {
			continue
		}
		if fld[5] != ifname {
			continue
		}
		flags, _ := strconv.ParseUint(fld[2], 0, 32)
		if flags&0x2 == 0 {
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
