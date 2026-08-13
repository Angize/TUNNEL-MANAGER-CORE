//go:build linux

package packet

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IP_PKTINFO plumbing for the raw carrier's destination rotation. A pooled server binds one raw socket to
// 0.0.0.0 and receives packets aimed at ANY of its IPs, but WriteToIP lets the kernel pick the reply
// source — so a client dialing a NON-primary pool IP gets an answer from the primary, its source filter
// drops it, and that pool IP burns. IP_PKTINFO reports the datagram's target and pins the reply to it.

// enablePktinfoDst turns on IP_PKTINFO so ReadMsgIP reports each datagram's destination address. It
// RETURNS the failure instead of swallowing it: without IP_PKTINFO the server silently reverts to the
// kernel-default reply source, which is exactly the bug this plumbing exists to prevent. The caller logs
// it; the fallback itself stays best-effort, since the socket is still usable.
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

// pktinfoOOB builds an IP_PKTINFO control message pinning the SOURCE (ipi_spec_dst) of an outgoing
// datagram to src, so conn.WriteMsgIP answers from the exact local IP the client dialed.
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

// cachedOOB is the control message pktinfoOOB built for one source. Every outbound packet of a
// pinned-source carrier needs it and it is 32 bytes of identical work each time; the source itself
// changes only on a rotation.
type cachedOOB struct {
	ip  net.IP
	oob []byte
}

// srcOOB is pktinfoOOB with the last answer kept. Concurrent senders only read the slice.
func (r *Raw) srcOOB(src net.IP) []byte {
	if c := r.oobSrc.Load(); c != nil && c.ip.Equal(src) {
		return c.oob
	}
	c := &cachedOOB{ip: append(net.IP(nil), src...), oob: pktinfoOOB(src)}
	r.oobSrc.Store(c)
	return c.oob
}

// pktinfoDst extracts the received datagram's DESTINATION IP from an IP_PKTINFO oob (nil if absent).
// The result ALIASES oob, which the receive loop reuses per packet — copy it to retain it.
// Inet4Pktinfo layout: ifindex(4) | spec_dst(4) | addr(4); addr (bytes 8:12) is ipi_addr, the header
// destination the SENDER aimed at, so it is attacker-chosen and says nothing about what we own.
// One message at a time, because the slice-returning parser allocates and this runs on every packet
// a server receives.
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

// sameIP4 reports whether an already-stored address is this one, without unwrapping either.
func sameIP4(cur *net.IP, ip net.IP) bool { return cur != nil && cur.Equal(ip) }

// localIPRescan bounds how often a miss re-reads the interface list. A pool IP the node adds at
// runtime has to be picked up, but a sender spraying unknown destinations must not be able to spin
// the scan on the receive path.
var localIPRescan = 5 * time.Second

// ourIPs answers the one question the receive path asks of ipi_addr: is that destination an address
// this host actually holds. Cached, because it is asked per packet.
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

// scanLocalIP4 is every IPv4 address currently configured on this host, keyed by its 4 bytes.
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
