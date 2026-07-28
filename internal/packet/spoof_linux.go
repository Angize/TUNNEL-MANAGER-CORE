//go:build linux

// The "spoof" transport is a standalone IP-spoofing carrier. It rides the same bip-like raw-IP
// datapath as the raw carrier (identical framing, AEAD, replay guard, ephemeral handshake,
// keepalive, FEC and TUN plumbing — all shared Raw code), but forges an outer IPv4 field:
//
//   - a forged SOURCE (spoof_src_ip): the client hides its real IP; the server is told the client's
//     real IP (real_peer_ip) to answer, since it can never learn it from the forged wire source.
//   - a forged DESTINATION = a decoy (spoof_dst_ip): the wire shows traffic to the decoy while the
//     packet is routed to the real server (only works when the decoy IP routes to that server, e.g.
//     an extra IP the provider maps to it). The server receives via AF_PACKET (the decoy is not a
//     local address, so an AF_INET raw socket would never see it) and answers AS the decoy.
//
// There is NO rotation of any kind here (neither source nor destination) — that is the whole reason
// spoofing was lifted out of raw: it is a different connection model, not a knob. The addressing is
// the forgedLink (iplink_linux.go); the constructors below only pick the forged fields and open the
// IP_HDRINCL / AF_PACKET sockets the link needs.
package packet

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// DialSpoof (client role) opens a spoof carrier toward peerIP, forging the outer source and/or
// destination. At least one of spoofSrc / spoofDst must be set (a carrier that forges nothing is
// just raw bip — config validation enforces this, and so does the guard below). rawProto (1..255,
// 0 = bip's native 253) overrides the outer IP protocol number to slip past a protocol whitelist.
func DialSpoof(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, spoofSrc, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	r, err := dialRawBase(peerIP, dev, ka, obfs, cryptoOn, psk, cipher, "bip", rawProto)
	if err != nil {
		return nil, err
	}
	var spoofSrcIP, spoofDstIP net.IP
	if spoofSrc != "" { // forge the outer source; conn still receives replies at our real IP
		if spoofSrcIP = parseIP4(spoofSrc); spoofSrcIP == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: spoof_src_ip %q is not an IPv4 address", spoofSrc)
		}
	}
	if spoofDst != "" { // forge the outer destination to the decoy; routing still targets the real peer
		if spoofDstIP = parseIP4(hostOnly(spoofDst)); spoofDstIP == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: spoof_dst_ip %q is not an IPv4 address", spoofDst)
		}
	}
	if spoofSrcIP == nil && spoofDstIP == nil {
		r.conn.Close()
		return nil, fmt.Errorf("spoof: needs a forged source or destination (a carrier that forges nothing is just raw bip)")
	}
	fd, err := openHdrincl(r.proto) // the forged header is built and sent via IP_HDRINCL
	if err != nil {
		r.conn.Close()
		return nil, fmt.Errorf("spoof: IP_HDRINCL socket: %w", err)
	}
	r.link = &forgedLink{r: r, spoofFd: fd, pktFd: -1, spoofSrc: spoofSrcIP, spoofDst: spoofDstIP}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}

// ListenSpoof (server role) binds a spoof carrier. realPeer is the client's real IP to answer (the
// forged source hides it from the wire, so the server can never learn it). When spoofDst is set the
// clients aim at that decoy: the server receives those frames via AF_PACKET (the decoy is not a local
// address) and answers AS the decoy. realPeer is required in both cases (config validation enforces it).
func ListenSpoof(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, realPeer, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	r, err := listenRawBase(listenIP, dev, ka, obfs, cryptoOn, psk, cipher, "bip", rawProto)
	if err != nil {
		return nil, err
	}
	var fixedPeer net.IP
	if realPeer != "" { // client forges its source, so we can't learn it — reply to this real IP
		if fixedPeer = parseIP4(hostOnly(realPeer)); fixedPeer == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: real_peer_ip %q is not an IPv4 address", realPeer)
		}
		r.peer.Store(&net.IPAddr{IP: fixedPeer})
		if lip := routeLocalIP(fixedPeer); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	if spoofDst != "" { // clients aim at this decoy; receive it via AF_PACKET and answer AS it
		dip := parseIP4(hostOnly(spoofDst))
		if dip == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: spoof_dst_ip %q is not an IPv4 address", spoofDst)
		}
		fd, err := openHdrincl(r.proto)
		if err != nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: IP_HDRINCL socket: %w", err)
		}
		pfd, err := openAfpacket()
		if err != nil {
			syscall.Close(fd)
			r.conn.Close()
			return nil, fmt.Errorf("spoof: AF_PACKET socket: %w", err)
		}
		// decoy = the AF_PACKET receive filter; spoofSrc = dip so replies leave AS the decoy.
		r.link = &forgedLink{r: r, spoofFd: fd, pktFd: pfd, spoofSrc: dip, decoy: dip,
			fixedPeer: fixedPeer, antiLeak: addAntiLeak(r.proto, dip)} // anti-leak best-effort; stops the kernel forwarding the decoy dst
		// NO applyConnSockBuf here on purpose: this link receives via pktFd and sends via spoofFd, so
		// r.conn is never read and never written. Sizing it pinned the whole sock_buf (4 MiB by default)
		// on a socket nothing drains — and the kernel would keep queuing matching frames into it forever.
	} else {
		// The client forges only its SOURCE (no decoy): we receive on the normal conn and forge
		// nothing on our replies, but the reply target is the configured real peer, not the wire
		// source, and the source filter must be off (a forged source can't be filtered by).
		r.link = &forgedLink{r: r, spoofFd: -1, pktFd: -1, fixedPeer: fixedPeer}
		applyConnSockBuf(r.conn) // this branch DOES send and receive on the conn
	}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}
