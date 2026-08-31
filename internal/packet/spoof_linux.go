//go:build linux

package packet

import (
	"fmt"
	"net"
	"syscall"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

func DialSpoof(peerIP string, dev *tun.Device, obfs bool, psk, cipher, spoofSrc, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	r, err := dialRawBase(peerIP, dev, obfs, psk, cipher, "bare", rawProto, 0)
	if err != nil {
		return nil, err
	}
	var spoofSrcIP, spoofDstIP net.IP
	if spoofSrc != "" {
		if spoofSrcIP = parseIP4(spoofSrc); spoofSrcIP == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: spoof_src_ip %q is not an IPv4 address", spoofSrc)
		}
	}
	if spoofDst != "" {
		if spoofDstIP = parseIP4(hostOnly(spoofDst)); spoofDstIP == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: spoof_dst_ip %q is not an IPv4 address", spoofDst)
		}
	}
	if spoofSrcIP == nil && spoofDstIP == nil {
		r.conn.Close()
		return nil, fmt.Errorf("spoof: needs a forged source or destination (a carrier that forges nothing is just raw bare)")
	}
	fd, err := openHdrincl(r.proto)
	if err != nil {
		r.conn.Close()
		return nil, fmt.Errorf("spoof: IP_HDRINCL socket: %w", err)
	}
	r.link = &forgedLink{r: r, spoofFd: fd, pktFd: -1, spoofSrc: spoofSrcIP, spoofDst: spoofDstIP}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}

func ListenSpoof(listenIP string, dev *tun.Device, obfs bool, psk, cipher, realPeer, spoofDst string, fec bool, fecData, fecParity, rawProto int) (*Raw, error) {
	r, err := listenRawBase(listenIP, dev, obfs, psk, cipher, "bare", rawProto, 0)
	if err != nil {
		return nil, err
	}
	var fixedPeer net.IP
	if realPeer != "" {
		if fixedPeer = parseIP4(hostOnly(realPeer)); fixedPeer == nil {
			r.conn.Close()
			return nil, fmt.Errorf("spoof: real_peer_ip %q is not an IPv4 address", realPeer)
		}
		r.peer.Store(&net.IPAddr{IP: fixedPeer})
		if lip := routeLocalIP(fixedPeer); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
	if spoofDst != "" {
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
		pfd, err := openAfpacket(bpfIPProtoDst(r.proto, dip), "spoof: decoy receive")
		if err != nil {
			syscall.Close(fd)
			r.conn.Close()
			return nil, fmt.Errorf("spoof: AF_PACKET socket: %w", err)
		}

		r.link = &forgedLink{r: r, spoofFd: fd, pktFd: pfd, spoofSrc: dip, decoy: dip,
			fixedPeer: fixedPeer, antiLeak: addAntiLeak(r.proto, dip, r.tunName())}
	} else {
		r.link = &forgedLink{r: r, spoofFd: -1, pktFd: -1, fixedPeer: fixedPeer}
		applyConnSockBuf(r.conn)
	}
	r.initFec(fec, fecData, fecParity)
	return r, nil
}
