//go:build linux

package packet

import (
	"net"
)

type ipLink interface {
	send(pkt []byte, to *net.IPAddr)

	recvLoop() error

	close()
}

type directLink struct{ r *Raw }

func (l *directLink) send(pkt []byte, to *net.IPAddr) { sendViaConn(l.r, pkt, to) }
func (l *directLink) recvLoop() error                 { return l.r.recvConnLoop() }
func (l *directLink) close()                          {}

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
