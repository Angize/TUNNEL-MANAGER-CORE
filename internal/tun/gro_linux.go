//go:build linux

// Joining a run of one connection's TCP segments into a single virtio super-packet, so the kernel is
// handed one packet where it used to be handed a dozen. The write-side mirror of splitGSO: there the
// kernel hands us a super-packet to cut up, here we hand it one to cut up itself.
//
// The TUN write was the last path still making a syscall per packet, and on a receiving node it is
// where most of the process's time went.
//
// The kernel's rule is that every segment but the last is the same size and carries the same header, so
// a run is joined only while that holds: one connection, consecutive sequence numbers, byte-identical
// headers, and no flag that means anything beyond "more data". Anything else ends the run and goes on
// its own, which is exactly what happened to every packet before.
package tun

import (
	"bytes"
	"encoding/binary"
)

const (
	// groMaxBytes bounds one super-packet. The IPv4 total-length field stops at 64 KiB and so does the
	// kernel, and crossing either fails the whole write rather than trimming it.
	groMaxBytes = 60000
	// groMaxSegs bounds how many packets one write may join, so its iovec array fits on the stack.
	groMaxSegs = 64

	tcpFIN = 0x01
	tcpPSH = 0x08
	tcpACK = 0x10
)

// tcpSeg is what one packet must agree on for the next to join it. ok is false for anything that is not
// a whole, unfragmented IPv4/IPv6 TCP segment carrying data -- those are never joined.
type tcpSeg struct {
	ok      bool
	v6      bool
	ipHdr   int // where the TCP header starts (IPv6: past the extension chain)
	l4Hdr   int // TCP header length, options included
	seq     uint32
	payload int
	flags   byte
}

func parseTCPSeg(pkt []byte) (s tcpSeg) {
	if len(pkt) < 20 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if pkt[9] != 6 { // protocol
			return
		}
		// A fragment carries no complete TCP header of its own, and the more-fragments bit says another
		// piece is coming: neither is a segment this may reason about.
		if pkt[6]&0x3f != 0 || pkt[7] != 0 {
			return
		}
		s.ipHdr = int(pkt[0]&0x0f) * 4
		if s.ipHdr < 20 || int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
			return // a header length or a total length that disagrees with the buffer: leave it alone
		}
	case 6:
		off, proto, ok := ipv6L4Offset(pkt)
		if !ok || proto != 6 {
			return
		}
		s.v6, s.ipHdr = true, off
		if 40+int(binary.BigEndian.Uint16(pkt[4:6])) != len(pkt) {
			return
		}
	default:
		return
	}
	if len(pkt) < s.ipHdr+20 {
		return
	}
	s.l4Hdr = int(pkt[s.ipHdr+12]>>4) * 4
	if s.l4Hdr < 20 || len(pkt) < s.ipHdr+s.l4Hdr {
		return
	}
	s.payload = len(pkt) - s.ipHdr - s.l4Hdr
	s.flags = pkt[s.ipHdr+13]
	s.seq = binary.BigEndian.Uint32(pkt[s.ipHdr+4 : s.ipHdr+8])
	s.ok = s.payload > 0
	return
}

// sameHeaders reports that b's headers are byte-identical to a's everywhere the kernel will not rewrite
// them itself. Every segment gets a COPY of the leader's header, so anything that differs -- a window
// update, a newer acknowledgement, a different timestamp option -- would be silently replaced by the
// leader's value. Requiring equality is what keeps that from happening.
func sameHeaders(a, b []byte, sa, sb tcpSeg) bool {
	if sa.v6 != sb.v6 || sa.ipHdr != sb.ipHdr || sa.l4Hdr != sb.l4Hdr {
		return false
	}
	if sa.v6 {
		// Everything but the payload length at [4:6]: version/class/flow, next header, hop limit,
		// addresses, and the whole extension chain.
		if !bytes.Equal(a[0:4], b[0:4]) || !bytes.Equal(a[6:sa.ipHdr], b[6:sb.ipHdr]) {
			return false
		}
	} else {
		// Everything but the total length and id at [2:6] and the header checksum at [10:12], both of
		// which the kernel writes per segment.
		if !bytes.Equal(a[0:2], b[0:2]) || !bytes.Equal(a[6:10], b[6:10]) ||
			!bytes.Equal(a[12:sa.ipHdr], b[12:sb.ipHdr]) {
			return false
		}
	}
	x, y := a[sa.ipHdr:], b[sb.ipHdr:]
	// Everything but the sequence number at [4:8], the flags at [13] and the checksum at [16:18].
	return bytes.Equal(x[0:4], y[0:4]) && // ports
		bytes.Equal(x[8:13], y[8:13]) && // acknowledgement, data offset
		bytes.Equal(x[14:16], y[14:16]) && // window
		bytes.Equal(x[18:sa.l4Hdr], y[18:sb.l4Hdr]) // urgent pointer, options
}

// groRun reports how many leading packets may go out as one super-packet, and the segment size the
// kernel must cut it back into. Fewer than two means there is nothing to join.
//
// PSH and a short payload both mean "this is the end of what the sender had", so either one closes the
// run: the kernel puts PSH on the last segment only, and every segment but the last must be full.
func groRun(pkts [][]byte) (n, segSize int) {
	if len(pkts) < 2 {
		return 0, 0
	}
	lead := parseTCPSeg(pkts[0])
	if !lead.ok || lead.flags != tcpACK {
		return 0, 0
	}
	segSize = lead.payload
	total := len(pkts[0])
	seq := lead.seq + uint32(lead.payload)
	n = 1
	for i := 1; i < len(pkts) && n < groMaxSegs; i++ {
		s := parseTCPSeg(pkts[i])
		if !s.ok || s.payload > segSize || total+s.payload > groMaxBytes ||
			s.seq != seq || s.flags&^tcpPSH != tcpACK || !sameHeaders(pkts[0], pkts[i], lead, s) {
			break
		}
		total += s.payload
		seq += uint32(s.payload)
		n++
		if s.payload < segSize || s.flags&tcpPSH != 0 {
			break
		}
	}
	if n < 2 {
		return 0, 0
	}
	return n, segSize
}

// writeSuper rewrites the leading packet into the header of the whole run and writes the lot as one
// packet: the leader entire, then each follower's PAYLOAD, gathered by the kernel. Nothing is copied.
//
// The leader is the caller's to change -- every carrier hands over a buffer built for this one frame --
// and it is written before this returns.
func (d *Device) writeSuper(pkts [][]byte, segSize int) error {
	lead := pkts[0]
	s := parseTCPSeg(lead)
	hdrLen := s.ipHdr + s.l4Hdr

	body := s.payload
	for _, p := range pkts[1:] {
		body += len(p) - hdrLen
	}
	l4Len := s.l4Hdr + body

	if s.v6 {
		binary.BigEndian.PutUint16(lead[4:6], uint16(s.ipHdr-40+l4Len))
	} else {
		binary.BigEndian.PutUint16(lead[2:4], uint16(s.ipHdr+l4Len))
		lead[10], lead[11] = 0, 0
		binary.BigEndian.PutUint16(lead[10:12], ipChecksum(lead[:s.ipHdr]))
	}
	// The run ends where the sender's data ended, so the push belongs on the last segment -- which is
	// where the kernel puts it, having cleared it from every other copy of this header.
	lead[s.ipHdr+13] |= parseTCPSeg(pkts[len(pkts)-1]).flags & tcpPSH
	// NEEDS_CSUM below means the checksum field holds the pseudo-header sum and the kernel finishes it
	// per segment. Writing a complete checksum here would be wrong twice: it is not what that flag
	// promises, and no single value is correct for segments of different lengths.
	binary.BigEndian.PutUint16(lead[s.ipHdr+16:s.ipHdr+18], pseudoSum(lead, s.ipHdr, s.v6, 6, l4Len))

	var vnet [vnetHdrLen]byte
	vnet[0] = vnetNeedsCsum
	vnet[1] = gsoTCPv4
	if s.v6 {
		vnet[1] = gsoTCPv6
	}
	binary.LittleEndian.PutUint16(vnet[2:4], uint16(hdrLen))
	binary.LittleEndian.PutUint16(vnet[4:6], uint16(segSize))
	binary.LittleEndian.PutUint16(vnet[6:8], uint16(s.ipHdr))
	binary.LittleEndian.PutUint16(vnet[8:10], 16)

	_, err := d.wrvGSO(vnet[:], lead, pkts[1:], hdrLen)
	return err
}

// WriteBatch hands a run of L3 packets to the kernel in arrival order, joining what can be joined. It
// reports the first write that failed; the rest of the run still goes, because a packet dropped here is
// a packet the tunnelled connection has to retransmit.
//
// Without the virtio header there is nothing to join into, so a device opened WITHOUT gso writes each
// packet exactly as it did before.
func (d *Device) WriteBatch(pkts [][]byte) error {
	var ferr error
	note := func(err error) {
		if err != nil && ferr == nil {
			ferr = err
		}
	}
	if !d.gso {
		for _, p := range pkts {
			_, err := d.Write(p)
			note(err)
		}
		return ferr
	}
	for i := 0; i < len(pkts); {
		n, segSize := groRun(pkts[i:])
		if n < 2 {
			_, err := d.Write(pkts[i])
			note(err)
			i++
			continue
		}
		if err := d.writeSuper(pkts[i:i+n], segSize); err != nil {
			note(err)
		} else {
			d.nOut.Add(uint64(n))
			d.nWrites.Add(1)
		}
		i += n
	}
	return ferr
}

// pseudoSum is the pseudo-header half of l4Checksum, folded but NOT complemented: the partial the
// NEEDS_CSUM contract puts in the checksum field for the kernel to complete.
func pseudoSum(pkt []byte, ipHdrLen int, v6 bool, proto byte, l4Len int) uint16 {
	var s uint32
	if v6 {
		s = sumBytes(pkt[8:40], 0) // src(16)+dst(16)
	} else {
		s = sumBytes(pkt[12:20], 0) // src(4)+dst(4)
	}
	return fold(s + uint32(proto) + uint32(l4Len))
}
