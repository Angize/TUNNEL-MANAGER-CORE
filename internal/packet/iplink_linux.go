//go:build linux

package packet

import (
	"net"
)

func sendViaConn(r *Raw, pkt []byte, to *net.IPAddr) {
	if src := r.boundSrc(); src != nil {
		if _, _, err := r.out.WriteMsgIP(pkt, r.srcOOB(src), to); err == nil {
			return
		} else {
			r.sendErr.note("raw/bound-source", err)
			if rawChecksumBindsSource(r.profile) {
				return
			}
		}
	}
	if _, err := r.out.WriteToIP(pkt, to); err != nil {
		r.sendErr.note("raw", err)
	}
}
