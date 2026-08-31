//go:build linux

package packet

import (
	"net"
	"syscall"
)

type ipLink interface {
	send(pkt []byte, to *net.IPAddr)

	recvLoop() error

	replyTo(src *net.IPAddr) *net.IPAddr

	filterSrc() bool

	pinsSource() bool

	fakeFD() int

	header(realSrc net.IP, to *net.IPAddr) (src, dst net.IP)

	close()
}

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

type forgedLink struct {
	r         *Raw
	spoofFd   int
	pktFd     int
	spoofSrc  net.IP
	spoofDst  net.IP
	decoy     net.IP
	fixedPeer net.IP
	antiLeak  func()
}

func (l *forgedLink) send(pkt []byte, to *net.IPAddr) {
	r := l.r
	if l.spoofFd < 0 {
		sendViaConn(r, pkt, to)
		return
	}
	src, dst := l.header(r.srcIP(), to)
	out := buildIP4(src, dst, r.proto, pkt)
	if out == nil {
		return
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())

	r.sendMu.RLock()
	if !r.sendDown {
		if err := syscall.Sendto(l.spoofFd, out, 0, &sa); err != nil {
			r.sendErr.note("raw/spoof", err)
		}
	}
	r.sendMu.RUnlock()
}

func (l *forgedLink) recvLoop() error {
	if l.pktFd >= 0 {
		return l.afpacket()
	}
	return l.r.recvConnLoop()
}

func (l *forgedLink) afpacket() error {
	r := l.r
	return afpacketLoop(l.pktFd, r.closeCh, func(pkt []byte, ihl int) {
		if int(pkt[9]) != r.proto {
			return
		}
		if l.decoy != nil && !net.IP(pkt[16:20]).Equal(l.decoy) {
			return
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

func sendViaConn(r *Raw, pkt []byte, to *net.IPAddr) {
	if src := r.pinnedSrc(); src != nil {
		if _, _, err := r.conn.WriteMsgIP(pkt, r.srcOOB(src), to); err == nil {
			return
		} else {
			r.sendErr.note("raw/pinned-source", err)
			if rawChecksumBindsSource(r.profile) {
				return
			}
		}
	}
	if _, err := r.conn.WriteToIP(pkt, to); err != nil {
		r.sendErr.note("raw", err)
	}
}
