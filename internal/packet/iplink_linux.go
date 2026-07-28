//go:build linux

package packet

import (
	"net"
	"syscall"
)

// ipLink is the ONE thing that differs between an ordinary raw-IP carrier and a
// spoofing one: how a wrapped packet reaches the wire, how frames are received,
// where a server answers, and whether the peer source filter applies. Everything
// above it — the AEAD framing, replay guard, ephemeral handshake, keepalive,
// FEC, rotation and the TUN plumbing — is shared Raw code and must never be
// forked (a copied datapath is the exact class of bug this split exists to kill).
//
// Two implementations, chosen once at construction from the config:
//
//   - directLink: today's raw carrier. Sends on the AF_INET raw socket (r.conn),
//     receives on it, answers the packet's own source, and filters by the peer
//     source address. Nothing is forged.
//
//   - forgedLink: any configuration that forges an outer IPv4 field or pins the
//     reply address. It is parametric so it covers every spoof combination with
//     one type (the addressing axes are not independent, so two rigid types could
//     not express them):
//     spoofFd >=0  -> build the whole IPv4 header and Sendto it (else send on r.conn)
//     pktFd   >=0  -> receive decoy-dst frames via AF_PACKET (else receive on r.conn)
//     fixedPeer    -> the client forged its source, so answer this configured IP
//     spoofSrc/Dst -> forge the outer source / destination
//
// A pure header() method returns the (src,dst) an outgoing packet should carry;
// it opens no socket, so its full matrix is unit-testable without CAP_NET_RAW.
type ipLink interface {
	// send ships one already-wrapped packet toward the real peer `to`.
	send(pkt []byte, to *net.IPAddr)
	// recvLoop runs the receive loop until the socket closes, handing each
	// authenticated-candidate frame to r.handleRaw. Blocks; returns on error/close.
	recvLoop() error
	// replyTo is the address a server answers `src` from — the packet source
	// normally, or the configured real peer when the client forged its source.
	replyTo(src *net.IPAddr) *net.IPAddr
	// filterSrc reports whether the peer source-address filter applies on receive.
	// False when the source is forged/pinned (a forged source can't be filtered by;
	// the AEAD still authenticates every frame).
	filterSrc() bool
	// pinsSource reports whether the outer source is a fixed forged decoy, so a
	// source-rotation pool must not also drive it.
	pinsSource() bool
	// fakeFD is the IP_HDRINCL socket the fake-desync decoys may borrow (-1 if none,
	// in which case SetDesync opens a dedicated one).
	fakeFD() int
	// header returns the outer (src,dst) an outgoing packet carries: the real
	// addresses for a direct link, the forged ones where configured.
	header(realSrc net.IP, to *net.IPAddr) (src, dst net.IP)
	// close releases the link's own sockets and any kernel anti-leak rule. The
	// caller (Raw.Close) has already flipped sendDown under sendMu.
	close()
}

// --- directLink: the unforged raw carrier (today's default path) ---------------

type directLink struct{ r *Raw }

func (l *directLink) send(pkt []byte, to *net.IPAddr)     { sendViaConn(l.r, pkt, to) }
func (l *directLink) recvLoop() error                     { return l.r.recvConnLoop() }
func (l *directLink) replyTo(src *net.IPAddr) *net.IPAddr { return src }
func (l *directLink) filterSrc() bool                     { return true }
func (l *directLink) pinsSource() bool                    { return false }
func (l *directLink) fakeFD() int                         { return -1 }
func (l *directLink) close()                              {}

func (l *directLink) header(realSrc net.IP, to *net.IPAddr) (net.IP, net.IP) {
	return realSrc, to.IP
}

// --- forgedLink: any forged-outer-field / pinned-reply configuration -----------

type forgedLink struct {
	r         *Raw
	spoofFd   int    // AF_INET SOCK_RAW + IP_HDRINCL sender (-1 => send on r.conn like a direct link)
	pktFd     int    // AF_PACKET receiver for decoy-dst frames (-1 => receive on r.conn)
	spoofSrc  net.IP // forged outer source (nil => real source)
	spoofDst  net.IP // forged outer destination = the decoy, client side (nil => real destination)
	decoy     net.IP // AF_PACKET receive filter: the decoy destination (server side)
	fixedPeer net.IP // the client's real IP to answer, when its source is forged (nil => answer the packet source)
	antiLeak  func() // removes the kernel anti-leak (iptables) rule on Close (nil if not installed)
}

func (l *forgedLink) send(pkt []byte, to *net.IPAddr) {
	r := l.r
	if l.spoofFd < 0 { // forged reply address but no header forging (spoof-src-only server): plain conn send
		sendViaConn(r, pkt, to)
		return
	}
	src, dst := l.header(r.srcIP(), to)
	out := buildIP4(src, dst, r.proto, pkt)
	if out == nil {
		return // oversize for the IPv4 length field (not reachable under normal MTUs)
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	// Guard the bare-fd Sendto so Close() can wait for in-flight sends and flip sendDown
	// before syscall.Close(spoofFd) — else a sibling goroutine could Sendto on a reused fd.
	r.sendMu.RLock()
	if !r.sendDown {
		if err := syscall.Sendto(l.spoofFd, out, 0, &sa); err != nil {
			r.sendErr.note("raw/spoof", err)
		}
	}
	r.sendMu.RUnlock()
}

func (l *forgedLink) recvLoop() error {
	if l.pktFd >= 0 { // decoy server: the real dst isn't local, so read raw frames off the wire
		return l.afpacket()
	}
	return l.r.recvConnLoop()
}

// afpacket receives frames aimed at the decoy destination off the wire via AF_PACKET.
// A decoy dst is not a local address, so the kernel would drop it before an AF_INET raw
// socket; AF_PACKET taps the packet before the IP stack's dst check. SOCK_DGRAM strips
// the link header, so each frame starts at the IP header.
func (l *forgedLink) afpacket() error {
	r := l.r
	return afpacketLoop(l.pktFd, r.closeCh, func(pkt []byte, ihl int) {
		if int(pkt[9]) != r.proto {
			return // not our carrier protocol
		}
		if l.decoy != nil && !net.IP(pkt[16:20]).Equal(l.decoy) {
			return // only frames aimed at our decoy destination
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		r.handleRaw(pkt[ihl:], src)
	})
}

func (l *forgedLink) replyTo(src *net.IPAddr) *net.IPAddr {
	if l.fixedPeer != nil {
		return &net.IPAddr{IP: l.fixedPeer}
	}
	return src
}

// filterSrc is off when the reply target is pinned (fixedPeer) or the server answers as a
// decoy the client aims at (client + spoofDst), because in both cases the peer's on-wire
// source is not the address to filter by — the AEAD authenticates every frame instead.
func (l *forgedLink) filterSrc() bool {
	return l.fixedPeer == nil && !(l.r.isClient && l.spoofDst != nil)
}

func (l *forgedLink) pinsSource() bool { return l.spoofSrc != nil }
func (l *forgedLink) fakeFD() int      { return l.spoofFd }

func (l *forgedLink) header(realSrc net.IP, to *net.IPAddr) (net.IP, net.IP) {
	src, dst := realSrc, to.IP
	if l.spoofSrc != nil {
		src = l.spoofSrc
	}
	if l.spoofDst != nil {
		dst = l.spoofDst
	}
	return src, dst
}

func (l *forgedLink) close() {
	if l.antiLeak != nil {
		l.antiLeak()
	}
	if l.spoofFd >= 0 {
		syscall.Close(l.spoofFd)
	}
	if l.pktFd >= 0 {
		syscall.Close(l.pktFd)
	}
}

// sendViaConn is the shared unforged send: pin the source via IP_PKTINFO when one is set
// (a server's dialed-reply IP, or a client's source-pool IP), else let the kernel route.
// Used by directLink and by a forgedLink that forges no header (a spoof-src-only server).
func sendViaConn(r *Raw, pkt []byte, to *net.IPAddr) {
	if src := r.pinnedSrc(); src != nil {
		if _, _, err := r.conn.WriteMsgIP(pkt, pktinfoOOB(src), to); err == nil {
			return
		} else {
			// Degrade to a default-source send rather than dropping — but say so. The pinned source is
			// normally one of our own local IPs, so this means it stopped being one mid-session (a pool
			// IP removed from the interface, a provider agent re-adding a secondary after a flap). Every
			// reply then leaves from the host default, the peer's source filter drops it, and the tunnel
			// blackholes. #151 made the setsockopt and missing-cmsg cases loud; this was the third.
			r.sendErr.note("raw/pinned-source", err)
		}
	}
	if _, err := r.conn.WriteToIP(pkt, to); err != nil {
		r.sendErr.note("raw", err)
	}
}
