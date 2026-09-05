//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestRawLivePathIsTheBytesOnTheWire(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	for _, profile := range []string{"tcp", "udp"} {
		for _, cport := range []uint32{0, 41207} {
			r := &Raw{profile: profile, isClient: true, port: 8443}
			r.cliPort.Store(cport)
			r.soloPeer.Store(&net.IPAddr{IP: dst})
			r.localIP.Store(&net.IPAddr{IP: src})

			k, _ := r.livePath()
			pkt := rawEncap(profile, []byte("payload"), src, dst, true, 0, r.port, r.cport(),
				0, 0, 0, 0, 0, tcpPshAck)
			wantS := binary.BigEndian.Uint16(pkt[0:2])
			wantD := binary.BigEndian.Uint16(pkt[2:4])

			if k.Sport != wantS || k.Dport != wantD {
				t.Errorf("raw/%s cliPort=%d: livePath says %d->%d, the wire carries %d->%d",
					profile, cport, k.Sport, k.Dport, wantS, wantD)
			}
			if k.Src != src.String() || k.Dst != dst.String() {
				t.Errorf("raw/%s cliPort=%d: livePath says %s->%s, want %s->%s",
					profile, cport, k.Src, k.Dst, src, dst)
			}
		}
	}
}

func TestPortlessRawProfileHasNoPortsInItsPath(t *testing.T) {
	for _, profile := range []string{"icmp", "bare"} {
		r := &Raw{profile: profile, isClient: true, port: 8443}
		r.cliPort.Store(41207)
		r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
		r.localIP.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, 1)})
		if k, _ := r.livePath(); k.Sport != 0 || k.Dport != 0 {
			t.Errorf("raw/%s: path carries ports %d->%d, but the profile puts none on the wire",
				profile, k.Sport, k.Dport)
		}
	}
}
