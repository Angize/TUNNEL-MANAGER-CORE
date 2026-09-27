//go:build linux

package tun

import "encoding/binary"

const (
	iffVnetHdr    = 0x4000
	tunSetOffload = 0x400454d0

	tunFCSUM = 0x01
	tunFTSO4 = 0x02
	tunFTSO6 = 0x04
	tunFUSO4 = 0x20
	tunFUSO6 = 0x40

	vnetHdrLen = 10

	gsoNone  = 0
	gsoTCPv4 = 1
	gsoTCPv6 = 4
	gsoUDPL4 = 5
	gsoECN   = 0x80

	vnetNeedsCsum = 0x01
)

type segCursor struct {
	pkt      []byte
	split    bool
	v6       bool
	isTCP    bool
	ipHdrLen int
	l4Hdr    int
	hdrLen   int
	gsoSize  int
	baseSeq  uint32
	flags    byte
	baseID   uint16
	off      int
	i        int
}

func (c *segCursor) empty() bool { return c.pkt == nil }

func (c *segCursor) load(pkt []byte, gsoSize, gsoType int) (split bool, segs int) {
	*c = segCursor{pkt: pkt}
	switch gsoType &^ gsoECN {
	case gsoTCPv4, gsoTCPv6:
		c.isTCP = true
	case gsoUDPL4:
	default:
		return false, 1
	}
	if !c.plan(gsoSize) {
		*c = segCursor{pkt: pkt}
		return false, 1
	}
	c.split = true
	return true, (len(pkt) - c.hdrLen + gsoSize - 1) / gsoSize
}

func (c *segCursor) plan(gsoSize int) bool {
	pkt := c.pkt
	c.v6 = pkt[0]>>4 == 6
	if c.v6 {
		l4Off, proto, ok := ipv6L4Offset(pkt)
		if !ok || (c.isTCP && proto != 6) || (!c.isTCP && proto != 17) {
			return false
		}
		c.ipHdrLen = l4Off
	} else {
		c.ipHdrLen = int(pkt[0]&0x0f) * 4
	}
	minL4 := 8
	if c.isTCP {
		minL4 = 20
	}
	if len(pkt) < c.ipHdrLen+minL4 {
		return false
	}
	c.l4Hdr = 8
	if c.isTCP {
		c.l4Hdr = int(pkt[c.ipHdrLen+12]>>4) * 4
		if c.l4Hdr < 20 {
			return false
		}
	}
	c.hdrLen = c.ipHdrLen + c.l4Hdr
	if len(pkt) <= c.hdrLen || gsoSize <= 0 {
		return false
	}
	c.gsoSize = gsoSize
	if c.isTCP {
		c.baseSeq = binary.BigEndian.Uint32(pkt[c.ipHdrLen+4 : c.ipHdrLen+8])
		c.flags = pkt[c.ipHdrLen+13]
	}
	if !c.v6 {
		c.baseID = binary.BigEndian.Uint16(pkt[4:6])
	}
	return true
}

func (c *segCursor) next(buf []byte) (n int, fits bool) {
	pkt := c.pkt
	if !c.split {
		c.pkt = nil
		if len(pkt) > len(buf) {
			return 0, false
		}
		return copy(buf, pkt), true
	}
	payload := pkt[c.hdrLen:]
	off, i := c.off, c.i
	end := off + c.gsoSize
	if end > len(payload) {
		end = len(payload)
	}
	chunk := payload[off:end]
	last := end == len(payload)
	c.off, c.i = end, i+1
	if last {
		c.pkt = nil
	}

	ipHdrLen := c.ipHdrLen
	size := c.hdrLen + len(chunk)
	if size > len(buf) {
		return 0, false
	}
	seg := buf[:size]
	copy(seg, pkt[:c.hdrLen])
	copy(seg[c.hdrLen:], chunk)

	if c.v6 {
		binary.BigEndian.PutUint16(seg[4:6], uint16((ipHdrLen-40)+c.l4Hdr+len(chunk)))
	} else {
		binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
		binary.BigEndian.PutUint16(seg[4:6], c.baseID+uint16(i))
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:12], ipChecksum(seg[:ipHdrLen]))
	}

	if c.isTCP {
		binary.BigEndian.PutUint32(seg[ipHdrLen+4:ipHdrLen+8], c.baseSeq+uint32(off))
		f := c.flags
		if !last {
			f &^= 0x09
		}
		seg[ipHdrLen+13] = f
		writeL4Csum(seg, ipHdrLen, c.v6, 6)
	} else {
		binary.BigEndian.PutUint16(seg[ipHdrLen+4:ipHdrLen+6], uint16(8+len(chunk)))
		writeL4Csum(seg, ipHdrLen, c.v6, 17)
	}
	return size, true
}

func writeL4Csum(pkt []byte, ipHdrLen int, v6 bool, proto byte) {
	off := ipHdrLen + 6
	if proto == 6 {
		off = ipHdrLen + 16
	}
	pkt[off], pkt[off+1] = 0, 0
	binary.BigEndian.PutUint16(pkt[off:off+2], l4Checksum(pkt, ipHdrLen, v6, proto))
}

func finalizeCsum(pkt []byte) {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int
	var proto byte
	if v6 {
		var ok bool
		ipHdrLen, proto, ok = ipv6L4Offset(pkt)
		if !ok {
			return
		}
	} else {
		if len(pkt) < 20 {
			return
		}
		ipHdrLen, proto = int(pkt[0]&0x0f)*4, pkt[9]
	}
	if len(pkt) < ipHdrLen+8 {
		return
	}
	switch proto {
	case 6:
		if len(pkt) < ipHdrLen+18 {
			return
		}
		writeL4Csum(pkt, ipHdrLen, v6, 6)
	case 17:
		writeL4Csum(pkt, ipHdrLen, v6, 17)
	}
}

func ipv6L4Offset(pkt []byte) (l4Off int, proto byte, ok bool) {
	if len(pkt) < 40 {
		return 0, 0, false
	}
	next := pkt[6]
	off := 40
	for {
		switch next {
		case 0, 43, 60:
			if off+2 > len(pkt) {
				return 0, 0, false
			}
			next = pkt[off]
			off += (int(pkt[off+1]) + 1) * 8
		case 44:
			if off+8 > len(pkt) {
				return 0, 0, false
			}
			next = pkt[off]
			off += 8
		default:
			if off > len(pkt) {
				return 0, 0, false
			}
			return off, next, true
		}
	}
}

func sumBytes(b []byte, init uint32) uint32 {
	sum := uint64(init)
	for len(b) >= 32 {
		v0 := binary.BigEndian.Uint64(b)
		v1 := binary.BigEndian.Uint64(b[8:])
		v2 := binary.BigEndian.Uint64(b[16:])
		v3 := binary.BigEndian.Uint64(b[24:])
		sum += v0>>32 + v0&0xffffffff
		sum += v1>>32 + v1&0xffffffff
		sum += v2>>32 + v2&0xffffffff
		sum += v3>>32 + v3&0xffffffff
		b = b[32:]
	}
	for len(b) >= 8 {
		v := binary.BigEndian.Uint64(b)
		sum += v>>32 + v&0xffffffff
		b = b[8:]
	}
	for len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}

	for sum>>32 != 0 {
		sum = (sum & 0xffffffff) + (sum >> 32)
	}
	return uint32(sum)
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

func ipChecksum(hdr []byte) uint16 { return ^fold(sumBytes(hdr, 0)) }

func l4Checksum(pkt []byte, ipHdrLen int, v6 bool, proto byte) uint16 {
	l4 := pkt[ipHdrLen:]
	var s uint32
	if v6 {
		s = sumBytes(pkt[8:40], 0)
	} else {
		s = sumBytes(pkt[12:20], 0)
	}
	s += uint32(proto)
	s += uint32(len(l4))
	c := ^fold(sumBytes(l4, s))
	if proto == 17 && c == 0 {
		c = 0xffff
	}
	return c
}
