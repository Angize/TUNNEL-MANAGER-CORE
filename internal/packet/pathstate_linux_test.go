//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestRawLivePathIsTheBytesOnTheWire.
//
// livePath names the path a verdict is keyed on. Checking it against rawPorts would prove nothing —
// that is the very call it makes. The claim worth pinning is that the key matches the BYTES rawEncap
// puts in the header, so a future change to either one that does not move the other fails here rather
// than in a misattributed burn.
func TestRawLivePathIsTheBytesOnTheWire(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	for _, profile := range []string{"tcp", "udp"} {
		for _, cport := range []uint32{0, 41207} { // the fixed default, and a rolled port
			r := &Raw{profile: profile, isClient: true, port: 8443}
			r.cliPort.Store(cport)
			r.peer.Store(&net.IPAddr{IP: dst})
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

// TestPortlessRawProfileHasNoPortsInItsPath.
//
// icmp and bare put no ports on the wire, so ports are not part of their path. Reporting the fixed
// defaults there would invent an axis the carrier does not have — and rawPorts answers whether or not
// the profile uses the answer.
func TestPortlessRawProfileHasNoPortsInItsPath(t *testing.T) {
	for _, profile := range []string{"icmp", "bare"} {
		r := &Raw{profile: profile, isClient: true, port: 8443}
		r.cliPort.Store(41207)
		r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, 2)})
		r.localIP.Store(&net.IPAddr{IP: net.IPv4(10, 0, 0, 1)})
		if k, _ := r.livePath(); k.Sport != 0 || k.Dport != 0 {
			t.Errorf("raw/%s: path carries ports %d->%d, but the profile puts none on the wire",
				profile, k.Sport, k.Dport)
		}
	}
}

// TestFluxLivePathIsTheBytesOnTheWire.
//
// flux derives its whole 4-tuple from (PSK, epoch) and redraws it every rotation, so the key must come
// from the SAME shape carrierSeg frames the packet with. Checked against the BYTES: the shape is the
// one thing on this carrier that moves with nothing announcing it, which is exactly what the epoch is
// there to catch, and a key reading a different shape than the wire would catch nothing.
func TestFluxLivePathIsTheBytesOnTheWire(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)
	carriersDiffered := false
	for _, epoch := range []int64{41, 42, 43} { // several, so the shape has to follow rather than stick
		for _, carrier := range []string{"udp", "stun"} {
			f := &Flux{carrier: carrier, isClient: true}
			sh := deriveFluxShape("lab-psk", epoch, "random")
			f.curShape.Store(&sh)
			f.peer.Store(&net.IPAddr{IP: dst})
			f.localIP.Store(&net.IPAddr{IP: src})

			k, ready := f.livePath()
			if ready {
				t.Errorf("flux/%s epoch %d: no session exists, so nothing may be judged on this path", carrier, epoch)
			}
			seg := f.carrierSeg([]byte("payload"), &sh, src, dst)
			wantS := binary.BigEndian.Uint16(seg[0:2])
			wantD := binary.BigEndian.Uint16(seg[2:4])
			if k.Sport != wantS || k.Dport != wantD {
				t.Errorf("flux/%s epoch %d: livePath says %d->%d, the wire carries %d->%d",
					carrier, epoch, k.Sport, k.Dport, wantS, wantD)
			}
			if k.Src != src.String() || k.Dst != dst.String() {
				t.Errorf("flux/%s epoch %d: livePath says %s->%s, want %s->%s",
					carrier, epoch, k.Src, k.Dst, src, dst)
			}
		}
		if sh := deriveFluxShape("lab-psk", epoch, "random"); sh.dport != sh.dportSTUN {
			carriersDiffered = true
		}
	}
	if !carriersDiffered {
		t.Fatal("every epoch drew the same port for both carriers, so nothing here would notice a key " +
			"that ignored the carrier — pick epochs where the two pools diverge")
	}
}
