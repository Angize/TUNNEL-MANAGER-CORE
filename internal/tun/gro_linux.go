//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
)

const (
	groMaxBytes = 60000

	groMaxSegs = 64

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

func parseTCPSeg(pkt []byte) (s tcpSeg) {
	if len(pkt) < 20 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if pkt[9] != 6 {
			return
		}

		if pkt[6]&0x3f != 0 || pkt[7] != 0 {
			return
		}
		s.ipHdr = int(pkt[0]&0x0f) * 4
		if s.ipHdr < 20 || int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) {
			return
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

func sameHeaders(a, b []byte, sa, sb tcpSeg) bool {
	if sa.v6 != sb.v6 || sa.ipHdr != sb.ipHdr || sa.l4Hdr != sb.l4Hdr {
		return false
	}
	if sa.v6 {
		if !bytes.Equal(a[0:4], b[0:4]) || !bytes.Equal(a[6:sa.ipHdr], b[6:sb.ipHdr]) {
			return false
		}
	} else {
		if !bytes.Equal(a[0:2], b[0:2]) || !bytes.Equal(a[6:10], b[6:10]) ||
			!bytes.Equal(a[12:sa.ipHdr], b[12:sb.ipHdr]) {
			return false
		}
	}
	x, y := a[sa.ipHdr:], b[sb.ipHdr:]

	return bytes.Equal(x[0:4], y[0:4]) &&
		bytes.Equal(x[8:13], y[8:13]) &&
		bytes.Equal(x[14:16], y[14:16]) &&
		bytes.Equal(x[18:sa.l4Hdr], y[18:sb.l4Hdr])
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

	lead[s.ipHdr+13] |= parseTCPSeg(pkts[len(pkts)-1]).flags & tcpPSH

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

func pseudoSum(pkt []byte, ipHdrLen int, v6 bool, proto byte, l4Len int) uint16 {
	var s uint32
	if v6 {
		s = sumBytes(pkt[8:40], 0)
	} else {
		s = sumBytes(pkt[12:20], 0)
	}
	return fold(s + uint32(proto) + uint32(l4Len))
}
