//go:build linux

package packet

import (
	"bytes"
	"net"
	"syscall"
)

// disorderTTL is the default TTL for a disorder/fake head or decoy segment when none is configured:
// low enough to expire before the server (so the on-path DPI, not the server, ingests it) yet high
// enough to pass the first few hops where a DPI usually sits.
const disorderTTL = 4

// TCP_REPAIR socket options (stable Linux ABI). They let us READ the connection's current send/recv
// sequence numbers without disturbing it — needed so a fake segment can overlap the real ClientHello
// at the exact sequence a stateful DPI reassembles on. We only read; we never rewind or write.
const (
	optTCPRepair      = 19 // TCP_REPAIR
	optTCPRepairQueue = 20 // TCP_REPAIR_QUEUE
	optTCPQueueSeq    = 21 // TCP_QUEUE_SEQ
	queueRecv         = 1  // TCP_RECV_QUEUE (kernel enum: NO_QUEUE=0, RECV=1, SEND=2)
	queueSend         = 2  // TCP_SEND_QUEUE

	// The two ways OUT of repair mode, which the kernel does NOT treat alike:
	repairOff        = 0  // TCP_REPAIR_OFF — also sends a window probe (a bare ACK) right away
	repairOffNoProbe = -1 // TCP_REPAIR_OFF_NO_WP — same, minus the probe. What we want; see readSeqs.
)

// ttlOpt returns the (level, option) pair for the hop-limit socket option of the connection's
// address family: IP_TTL for IPv4, IPV6_UNICAST_HOPS for IPv6. Using the IPv4 pair on an AF_INET6
// socket fails, which would silently disable disorder on an IPv6 edge.
func (f *fragConn) ttlOpt() (int, int) {
	if ra, ok := f.Conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() == nil && ra.IP.To16() != nil {
		return syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS
	}
	return syscall.IPPROTO_IP, syscall.IP_TTL
}

// writeDisorder sends the HEAD segment at a low TTL so it dies in transit — an on-path DPI ingests
// it but the server never does; the kernel then retransmits it at the normal TTL, so the server
// reassembles the real ClientHello while the DPI saw the segments out of order. It reaches under the
// TLS conn to the raw fd (net.TCPConn.SyscallConn) to set the hop limit per segment; TCP_NODELAY
// (Go's default) makes each Write flush a segment while its TTL is in effect. Falls back to a plain
// split when the raw fd is unavailable.
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
		f.degraded("setsockopt(TTL): " + cerr.Error()) // e.g. a container without the capability
		return f.writeSplit(p, at)                     // at least split
	}
	n1, werr := f.Conn.Write(p[:at]) // head flushed at the low TTL -> expires before the server
	_ = raw.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), level, opt, orig) // restore for the tail + retransmit
	})
	if werr != nil {
		return n1, werr
	}
	n2, werr := f.Conn.Write(p[at:])
	return n1 + n2, werr
}

// readSeqs briefly enters TCP_REPAIR mode on the (idle, established) socket at the ClientHello point
// to read the send and receive sequence numbers, then leaves it. Returns ok=false if any step
// fails. Read-only: it never changes a queue's contents or sequence, so it does not disturb the
// connection (this is the CRIU checkpoint path, done here on a connection with no in-flight data).
func readSeqs(raw syscall.RawConn) (snd, rcv uint32, ok bool) {
	_ = raw.Control(func(fd uintptr) {
		f := int(fd)
		if syscall.SetsockoptInt(f, syscall.IPPROTO_TCP, optTCPRepair, 1) != nil {
			return
		}
		// -1, not 0. The kernel treats them differently on the way OUT of repair mode: 0 also calls
		// tcp_send_window_probe(), which on an ESTABLISHED socket transmits a bare ACK immediately.
		// readSeqs runs on an idle, just-connected socket at the ClientHello point, so that ACK landed
		// between the handshake and the ClientHello on EVERY sni_mode=fake connection — an exchange
		// that appears on exactly the connections trying not to stand out. -1 leaves repair mode with
		// the identical effect and no probe.
		//
		// MEASURED on DE with tcpdump, not reasoned from the kernel source (which is what the finding
		// did): with 0 the capture carries an extra `Flags [.], ack 1` from us AND the peer's answering
		// ACK, and /proc/net/netstat's TCPWinProbe goes up by one; with -1 neither appears and the
		// counter does not move.
		//
		// Falling back to 0 if -1 is refused is not version tolerance for our own code — it is the one
		// case where failing is worse than the probe: a socket LEFT IN REPAIR MODE does not behave like
		// a TCP socket at all, and this deferred call is the only thing that takes it out.
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

// writeFake injects a fake ClientHello — a copy of the real one with the SNI overwritten by a decoy
// — as a raw TCP segment at the SAME sequence as the real ClientHello, carrying a deliberately BAD
// TCP checksum so the server's stack drops it. A stateful DPI reassembles the fake (decoy SNI) at
// that sequence and clears the flow; the server discards the fake (bad checksum) and gets the real
// ClientHello, written normally right after (the socket's sequence is untouched, because the fake
// goes out via AF_PACKET, not the socket). Killing by checksum instead of a low TTL is
// hop-independent — it works even when the server is a nearby CDN edge, where no TTL window exists.
// AF_PACKET SOCK_RAW hands the frame to the driver with CHECKSUM_NONE, so TX offload does not repair
// the checksum. This defeats a DPI that reassembles the stream — which plain split/disorder do not.
// IPv4 only (the raw injector builds IPv4); falls back to disorder on IPv6 or when any primitive is
// unavailable. Needs CAP_NET_RAW + CAP_NET_ADMIN, which the core holds (it runs as root).
func (f *fragConn) writeFake(p []byte, at int) (int, error) {
	// Build the decoy FIRST: it depends on nothing about the socket, and the one case that cannot
	// produce a decoy at all should not poke TCP_REPAIR or open an AF_PACKET socket on the way to
	// finding that out.
	fake := make([]byte, len(p))
	copy(fake, p)
	i := bytes.Index(fake, []byte(f.host))
	if i < 0 {
		// The hostname is not in the ClientHello in cleartext. With nothing to overwrite, the "decoy"
		// would be a BYTE-IDENTICAL copy of the real ClientHello, injected at the same sequence with a
		// corrupt checksum. A DPI resolving that overlap recovers exactly the SNI it would have seen
		// anyway: zero benefit, and a duplicate segment carrying a bad checksum is itself a signature.
		// So the fallback is right either way — but the REASON is not the same, and this used to name
		// ECH without being told whether ECH was on. Under ECH there is nothing left to hide; without
		// it, the hostname search simply failed and the real SNI is on the wire.
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
	if src == nil || dst == nil { // IPv6 -> the raw injector can't build it; disorder is the next best
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
		// TCP_REPAIR needs CAP_NET_ADMIN. Without the sequence numbers the decoy cannot be placed at
		// the same offset as the real ClientHello, which is the whole mechanism.
		f.fakeDegraded("TCP_REPAIR could not read the connection's sequence numbers (needs CAP_NET_ADMIN)")
		return f.writeDisorder(p, at)
	}
	inj, err := newL2Inject()
	if err != nil {
		f.fakeDegraded("AF_PACKET injector: " + err.Error())
		return f.writeDisorder(p, at)
	}
	defer inj.close()
	seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), snd, rcv, tcpPshAck, 0xffff, fake)
	badTCPChecksum(seg) // the SERVER drops the fake (bad L4 checksum); the DPI still ingests it
	if ip := buildIP4Ext(src, dst, protoTCP, f.fakeSegTTL(), false, seg); ip != nil {
		f.dsSend.note("tcp/sni-fake", inj.sendTo(dst, ip))
	}
	return f.Conn.Write(p) // the real ClientHello, whole, at the same sequence (socket untouched)
}
