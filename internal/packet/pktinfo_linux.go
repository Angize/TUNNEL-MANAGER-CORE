//go:build linux

package packet

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const pktinfoOOBLen = 128

func enablePktinfoDst(c *net.IPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}); cerr != nil {
		return cerr
	}
	return serr
}

func pktinfoOOB(src net.IP) []byte {
	v4 := src.To4()
	if v4 == nil {
		return nil
	}
	b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_IP
	h.Type = unix.IP_PKTINFO
	h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
	copy(pi.Spec_dst[:], v4)
	return b
}

func udpSegmentOOB(size int) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	*(*uint16)(unsafe.Pointer(&b[unix.CmsgLen(0)])) = uint16(size)
	return b
}

type cachedOOB struct {
	ip  net.IP
	oob []byte
}

func (r *Raw) srcOOB(src net.IP) []byte {
	if c := r.oobSrc.Load(); c != nil && c.ip.Equal(src) {
		return c.oob
	}
	c := &cachedOOB{ip: append(net.IP(nil), src...), oob: pktinfoOOB(src)}
	r.oobSrc.Store(c)
	return c.oob
}

func pktinfoDst(oob []byte) net.IP {
	for len(oob) > 0 {
		h, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return nil
		}
		if h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) >= 12 {
			return net.IP(data[8:12])
		}
		oob = rest
	}
	return nil
}

func sameIP4(cur *net.IP, ip net.IP) bool { return cur != nil && cur.Equal(ip) }

var localIPRescan = 5 * time.Second

type ourIPs struct {
	mu      sync.Mutex
	set     map[string]struct{}
	scanned time.Time
}

func (o *ourIPs) has(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	key := string(v4)
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.set[key]; ok {
		return true
	}
	if o.set != nil && time.Since(o.scanned) < localIPRescan {
		return false
	}
	o.set, o.scanned = scanLocalIP4(), time.Now()
	_, ok := o.set[key]
	return ok
}

func scanLocalIP4() map[string]struct{} {
	out := map[string]struct{}{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := n.IP.To4(); v4 != nil {
			out[string(v4)] = struct{}{}
		}
	}
	return out
}
