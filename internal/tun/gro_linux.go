//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
)

const (
	groMaxBytes = 60000

	groMaxSegs = 64

	udpHdrLen = 8

	tcpFIN = 0x01
	tcpPSH = 0x08
	tcpACK = 0x10
)

type tcpSeg struct {
	ok      bool
	v6      bool
	ipHdr   int
	l4Hdr   int
	seq     uint32
	payload int
	flags   byte
}

func ipShape(pkt []byte, proto byte) (ipHdr int, v6, ok bool) {
	if len(pkt) < 20 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if pkt[9] != proto || pkt[6]&0x3f != 0 || pkt[7] != 0 {
			return
		}
		ipHdr = int(pkt[0]&0x0f) * 4
		if ipHdr < 20 || int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
			return
		}
	case 6:
		off, p, o := ipv6L4Offset(pkt)
		if !o || p != proto {
			return
		}
		v6, ipHdr = true, off
		if 40+int(binary.BigEndian.Uint16(pkt[4:6])) != len(pkt) {
			return
		}
	default:
		return
	}
	return ipHdr, v6, true
}

func sameIPHeaders(a, b []byte, ipHdr int, v6 bool) bool {
	if v6 {
		return bytes.Equal(a[0:4], b[0:4]) && bytes.Equal(a[6:ipHdr], b[6:ipHdr])
	}
	return bytes.Equal(a[0:2], b[0:2]) && bytes.Equal(a[6:10], b[6:10]) &&
		bytes.Equal(a[12:ipHdr], b[12:ipHdr])
}

func parseTCPSeg(pkt []byte) (s tcpSeg) {
	ipHdr, v6, ok := ipShape(pkt, 6)
	if !ok {
		return
	}
	s.ipHdr, s.v6 = ipHdr, v6
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

func sameHeaders(a, b []byte, sa, sb tcpSeg) bool {
	if sa.v6 != sb.v6 || sa.ipHdr != sb.ipHdr || sa.l4Hdr != sb.l4Hdr {
		return false
	}
	if !sameIPHeaders(a, b, sa.ipHdr, sa.v6) {
		return false
	}
	x, y := a[sa.ipHdr:], b[sb.ipHdr:]

	return bytes.Equal(x[0:4], y[0:4]) &&
		bytes.Equal(x[8:13], y[8:13]) &&
		bytes.Equal(x[14:16], y[14:16]) &&
		bytes.Equal(x[18:sa.l4Hdr], y[18:sb.l4Hdr])
}

type udpSeg struct {
	ok      bool
	v6      bool
	ipHdr   int
	payload int
}

func parseUDPSeg(pkt []byte) (s udpSeg) {
	ipHdr, v6, ok := ipShape(pkt, 17)
	if !ok {
		return
	}
	s.ipHdr, s.v6 = ipHdr, v6
	if len(pkt) < s.ipHdr+udpHdrLen {
		return
	}
	s.payload = len(pkt) - s.ipHdr - udpHdrLen
	if int(binary.BigEndian.Uint16(pkt[s.ipHdr+4:s.ipHdr+6])) != udpHdrLen+s.payload {
		return
	}
	s.ok = s.payload > 0
	return
}

func sameUDPHeaders(a, b []byte, sa, sb udpSeg) bool {
	if sa.v6 != sb.v6 || sa.ipHdr != sb.ipHdr {
		return false
	}
	return sameIPHeaders(a, b, sa.ipHdr, sa.v6) &&
		bytes.Equal(a[sa.ipHdr:sa.ipHdr+4], b[sb.ipHdr:sb.ipHdr+4])
}

func udpRun(pkts [][]byte) (n, segSize int) {
	if len(pkts) < 2 {
		return 0, 0
	}
	lead := parseUDPSeg(pkts[0])
	if !lead.ok {
		return 0, 0
	}
	segSize = lead.payload
	total := len(pkts[0])
	n = 1
	for i := 1; i < len(pkts) && n < groMaxSegs; i++ {
		s := parseUDPSeg(pkts[i])
		if !s.ok || s.payload > segSize || total+s.payload > groMaxBytes ||
			!sameUDPHeaders(pkts[0], pkts[i], lead, s) {
			break
		}
		total += s.payload
		n++
		if s.payload < segSize {
			break
		}
	}
	if n < 2 {
		return 0, 0
	}
	return n, segSize
}

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

func (d *Device) writeSuper(pkts [][]byte, segSize int, proto byte) error {
	lead := pkts[0]
	ipHdr, l4Hdr, v6 := superShape(lead, proto)
	hdrLen := ipHdr + l4Hdr

	body := 0
	for _, p := range pkts {
		body += len(p) - hdrLen
	}
	l4Len := l4Hdr + body

	if v6 {
		binary.BigEndian.PutUint16(lead[4:6], uint16(ipHdr-40+l4Len))
	} else {
		binary.BigEndian.PutUint16(lead[2:4], uint16(ipHdr+l4Len))
		lead[10], lead[11] = 0, 0
		binary.BigEndian.PutUint16(lead[10:12], ipChecksum(lead[:ipHdr]))
	}

	var vnet [vnetHdrLen]byte
	csumOff := 16
	if proto == 17 {
		csumOff = 6
		vnet[1] = gsoUDPL4
		binary.BigEndian.PutUint16(lead[ipHdr+4:ipHdr+6], uint16(l4Len))
	} else {
		lead[ipHdr+13] |= parseTCPSeg(pkts[len(pkts)-1]).flags & tcpPSH
		vnet[1] = gsoTCPv4
		if v6 {
			vnet[1] = gsoTCPv6
		}
	}
	binary.BigEndian.PutUint16(lead[ipHdr+csumOff:ipHdr+csumOff+2], pseudoSum(lead, ipHdr, v6, proto, l4Len))

	vnet[0] = vnetNeedsCsum
	binary.LittleEndian.PutUint16(vnet[2:4], uint16(hdrLen))
	binary.LittleEndian.PutUint16(vnet[4:6], uint16(segSize))
	binary.LittleEndian.PutUint16(vnet[6:8], uint16(ipHdr))
	binary.LittleEndian.PutUint16(vnet[8:10], uint16(csumOff))

	_, err := d.wrvGSO(vnet[:], lead, pkts[1:], hdrLen)
	return err
}

func superShape(pkt []byte, proto byte) (ipHdr, l4Hdr int, v6 bool) {
	if proto == 17 {
		s := parseUDPSeg(pkt)
		return s.ipHdr, udpHdrLen, s.v6
	}
	s := parseTCPSeg(pkt)
	return s.ipHdr, s.l4Hdr, s.v6
}

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
		proto := byte(6)
		n, segSize := groRun(pkts[i:])
		if n < 2 && d.uso {
			if n, segSize = udpRun(pkts[i:]); n >= 2 {
				proto = 17
			}
		}
		if n < 2 {
			_, err := d.Write(pkts[i])
			note(err)
			i++
			continue
		}
		if err := d.writeSuper(pkts[i:i+n], segSize, proto); err != nil {
			note(err)
		} else {
			d.nOut.Add(uint64(n))
			d.nWrites.Add(1)
		}
		i += n
	}
	return ferr
}

func pseudoSum(pkt []byte, ipHdrLen int, v6 bool, proto byte, l4Len int) uint16 {
	var s uint32
	if v6 {
		s = sumBytes(pkt[8:40], 0)
	} else {
		s = sumBytes(pkt[12:20], 0)
	}
	return fold(s + uint32(proto) + uint32(l4Len))
}
