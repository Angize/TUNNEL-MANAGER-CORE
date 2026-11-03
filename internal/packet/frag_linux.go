//go:build linux

package packet

import (
	"bytes"
	"log"
	"net"
	"syscall"
)

const disorderTTL = 4

func (f *fragConn) degraded(why string) {
	f.warn.Do(func() {
		log.Printf("core/tls: sni_mode %q fell back to a plain split (%s) — the split still helps a stateless DPI, the desync does not apply", f.mode, why)
	})
}

func (f *fragConn) fakeDegraded(why string) {
	f.warnFake.Do(func() {
		log.Printf("core/tls: sni_mode \"fake\" fell back to disorder (%s) — disorder desyncs a DPI that "+
			"reads packets, but NOT one that reassembles the stream, which is the only thing fake buys", why)
	})
}

func badTCPChecksum(seg []byte) {
	if len(seg) < 18 {
		return
	}
	seg[16] ^= 0xff
}

var decoyApexes = []string{"b-cdn.net", "fastly.net", "azureedge.net", "cloudflare.com", "cdn.jsdelivr.net"}

func decoySNI(n int) []byte {
	if n <= 0 {
		return nil
	}

	for _, a := range decoyApexes {
		if len(a) == n {
			return []byte(a)
		}
	}

	apex := ""
	for _, a := range decoyApexes {
		if len(a)+2 <= n && len(a) > len(apex) {
			apex = a
		}
	}
	if apex == "" {
		return decoyLabels(n)
	}
	out := make([]byte, 0, n)
	out = append(out, decoyLabels(n-len(apex)-1)...)
	out = append(out, '.')
	return append(out, apex...)
}

func decoyLabels(n int) []byte {
	const fill = "assets"
	const maxLabel = 63
	out := make([]byte, 0, n)
	for len(out) < n {
		seg := n - len(out)
		if seg > maxLabel {
			seg = maxLabel
			if rem := n - len(out) - seg; rem < 2 {
				seg = n - len(out) - 2
			}
		}
		for i := 0; i < seg; i++ {
			out = append(out, fill[len(out)%len(fill)])
		}
		if len(out) < n {
			out = append(out, '.')
		}
	}
	return out
}

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
	f.dsSend.note("tcp/sni-fake", inj.sendTo(dst, buildIP4Ext(src, dst, protoTCP, badSumTTL, false, seg)))
	return f.Conn.Write(p)
}
