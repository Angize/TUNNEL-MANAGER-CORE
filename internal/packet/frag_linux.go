//go:build linux

package packet

import (
	"bytes"
	"net"
	"syscall"
)

const disorderTTL = 4

const (
	optTCPRepair      = 19
	optTCPRepairQueue = 20
	optTCPQueueSeq    = 21
	queueRecv         = 1
	queueSend         = 2

	repairOff        = 0
	repairOffNoProbe = -1
)

func (f *fragConn) ttlOpt() (int, int) {
	if ra, ok := f.Conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() == nil && ra.IP.To16() != nil {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

func (f *fragConn) writeDisorder(p []byte, at int) (int, error) {
	sc, ok := f.Conn.(syscall.Conn)
	if !ok {
		f.degraded("the connection exposes no raw fd")
		return f.writeSplit(p, at)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		f.degraded("SyscallConn: " + err.Error())
		return f.writeSplit(p, at)
	}
	level, opt := f.ttlOpt()
	ttl := f.ttl
	if ttl <= 0 {
		ttl = disorderTTL
	}
	orig := 64
	if cerr := raw.Control(func(fd uintptr) {
		if v, e := syscall.GetsockoptInt(int(fd), level, opt); e == nil && v > 0 {
			orig = v
		}
		syscall.SetsockoptInt(int(fd), level, opt, ttl)
	}); cerr != nil {
		f.degraded("setsockopt(TTL): " + cerr.Error())
		return f.writeSplit(p, at)
	}
	n1, werr := f.Conn.Write(p[:at])
	_ = raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), level, opt, orig)
	})
	if werr != nil {
		return n1, werr
	}
	n2, werr := f.Conn.Write(p[at:])
	return n1 + n2, werr
}

func readSeqs(raw syscall.RawConn) (snd, rcv uint32, ok bool) {
	_ = raw.Control(func(fd uintptr) {
		f := int(fd)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, 1) != nil {
			return
		}

		defer func() {
			if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, repairOffNoProbe) != nil {
				syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, repairOff)
			}
		}()
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepairQueue, queueSend) != nil {
			return
		}
		s, e1 := syscall.GetsockoptInt(f, syscall.IPPROTO_TCP, optTCPQueueSeq)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepairQueue, queueRecv) != nil {
			return
		}
		r, e2 := syscall.GetsockoptInt(f, syscall.IPPROTO_TCP, optTCPQueueSeq)
		if e1 == nil && e2 == nil {
			snd, rcv, ok = uint32(s), uint32(r), true
		}
	})
	return
}

func (f *fragConn) writeFake(p []byte, at int) (int, error) {
	fake := make([]byte, len(p))
	copy(fake, p)
	i := bytes.Index(fake, []byte(f.host))
	if i < 0 {
		why := "the hostname is not in the ClientHello in cleartext"
		if f.ech {
			why += " (ECH encrypts it)"
		} else {
			why += " and ECH is NOT on — check that ws_host matches the SNI this carrier dials with"
		}
		f.fakeDegraded(why + ", so the decoy would be byte-identical to the real one — injecting it " +
			"would add a signature and hide nothing")
		return f.writeDisorder(p, at)
	}
	copy(fake[i:i+len(f.host)], decoySNI(len(f.host)))

	la, ok1 := f.Conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := f.Conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		f.fakeDegraded("the connection is not TCP, so there is no 4-tuple to forge a segment on")
		return f.writeDisorder(p, at)
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil {
		f.fakeDegraded("the edge is IPv6 and the decoy injector builds IPv4 only")
		return f.writeDisorder(p, at)
	}
	sc, ok := f.Conn.(syscall.Conn)
	if !ok {
		f.fakeDegraded("the connection exposes no raw fd")
		return f.writeDisorder(p, at)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		f.fakeDegraded("SyscallConn: " + err.Error())
		return f.writeDisorder(p, at)
	}
	snd, rcv, ok := readSeqs(raw)
	if !ok {
		f.fakeDegraded("TCP_REPAIR could not read the connection's sequence numbers (needs CAP_NET_ADMIN)")
		return f.writeDisorder(p, at)
	}
	inj, err := newL2Inject()
	if err != nil {
		f.fakeDegraded("AF_PACKET injector: " + err.Error())
		return f.writeDisorder(p, at)
	}
	defer inj.close()

	opts, window := tcpDecoyShape(f.Conn)
	seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), snd, rcv, tcpPshAck, window, opts, fake)
	badTCPChecksum(seg)
	if ip := buildIP4Ext(src, dst, protoTCP, f.fakeSegTTL(), false, seg); ip != nil {
		f.dsSend.note("tcp/sni-fake", inj.sendTo(dst, ip))
	}
	return f.Conn.Write(p)
}
