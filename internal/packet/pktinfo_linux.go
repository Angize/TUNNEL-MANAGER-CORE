//go:build linux

package packet

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// IP_PKTINFO plumbing for the raw carrier's destination-rotation fix. A pooled server binds one raw
// socket to 0.0.0.0 and receives packets aimed at ANY of its IPs, but net.IPConn.WriteToIP lets the
// kernel pick the reply source (its default/primary IP) — so when the client dials a NON-primary pool
// IP, the reply comes from the primary, the client's source filter drops it, and that pool IP burns.
// IP_PKTINFO closes the loop: on receive it reports which of our IPs the datagram targeted, and on
// send it pins the source to that same IP — so the server answers FROM the exact IP the client dialed.

// enablePktinfoDst turns on IP_PKTINFO so ReadMsgIP reports each datagram's destination address.
// It RETURNS the failure instead of swallowing it. Without IP_PKTINFO the server silently reverts to
// the kernel-default reply source — i.e. exactly the destination-rotation bug this plumbing exists to
// prevent, but with nothing in the logs or the status file to show for it. The caller logs it so the
// degradation is loud; the fallback itself stays best-effort (the socket is still usable).
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

// pktinfoDst extracts the received datagram's DESTINATION IP from an IP_PKTINFO oob (nil if absent).
// It returns a fresh copy, safe to retain. Inet4Pktinfo layout: ifindex(4) | spec_dst(4) | addr(4);
// addr (bytes 8:12) is ipi_addr, the header destination the sender aimed at.
func pktinfoDst(oob []byte) net.IP {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO && len(m.Data) >= 12 {
			return net.IP(append([]byte(nil), m.Data[8:12]...))
		}
	}
	return nil
}
