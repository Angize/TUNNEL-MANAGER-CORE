//go:build linux

package tun

import "encoding/binary"

const (
	iffVnetHdr    = 0x4000
	tunSetOffload = 0x400454d0

	tunFCSUM = 0x01
	tunFTSO4 = 0x02
	tunFTSO6 = 0x04

	vnetHdrLen = 10

	gsoNone  = 0
	gsoTCPv4 = 1
	gsoUFO   = 3
	gsoTCPv6 = 4
	gsoUDPL4 = 5
	gsoECN   = 0x80

	vnetNeedsCsum = 0x01
)

func splitGSO(pkt []byte, gsoSize, gsoType int) (segs [][]byte, split bool) {
	switch gsoType &^ gsoECN {
	case gsoTCPv4, gsoTCPv6:
		return segment(pkt, gsoSize, true)
	case gsoUDPL4:
		return segment(pkt, gsoSize, false)
	default:
		return [][]byte{pkt}, false
	}
}

func segment(pkt []byte, gsoSize int, isTCP bool) (segs [][]byte, split bool) {
	v6 := pkt[0]>>4 == 6
	var ipHdrLen int
	if v6 {
		l4Off, proto, ok := ipv6L4Offset(pkt)
		if !ok || (isTCP && proto != 6) || (!isTCP && proto != 17) {
			return [][]byte{pkt}, false
		}
		ipHdrLen = l4Off
	} else {
		ipHdrLen = int(pkt[0]&0x0f) * 4
	}
	minL4 := 8
	if isTCP {
		minL4 = 20
	}
	if len(pkt) < ipHdrLen+minL4 {
		return [][]byte{pkt}, false
	}
	l4Hdr := 8
	if isTCP {
		l4Hdr = int(pkt[ipHdrLen+12]>>4) * 4
		if l4Hdr < 20 {
			return [][]byte{pkt}, false
		}
	}
	hdrLen := ipHdrLen + l4Hdr
	if len(pkt) <= hdrLen || gsoSize <= 0 {
		return [][]byte{pkt}, false
	}
	payload := pkt[hdrLen:]

	var baseSeq uint32
	var flags byte
	if isTCP {
		baseSeq = binary.BigEndian.Uint32(pkt[ipHdrLen+4 : ipHdrLen+8])
		flags = pkt[ipHdrLen+13]
	}
	var baseID uint16
	if !v6 {
		baseID = binary.BigEndian.Uint16(pkt[4:6])
	}

	var out [][]byte
	for off, i := 0, 0; off < len(payload); off, i = off+gsoSize, i+1 {
		end := off + gsoSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		last := end == len(payload)

		seg := make([]byte, hdrLen+len(chunk))
		copy(seg, pkt[:hdrLen])
		copy(seg[hdrLen:], chunk)

		if v6 {
			binary.BigEndian.PutUint16(seg[4:6], uint16((ipHdrLen-40)+l4Hdr+len(chunk)))
		} else {
			binary.BigEndian.PutUint16(seg[2:4], uint16(len(seg)))
			binary.BigEndian.PutUint16(seg[4:6], baseID+uint16(i))
			seg[10], seg[11] = 0, 0
			binary.BigEndian.PutUint16(seg[10:12], ipChecksum(seg[:ipHdrLen]))
		}

		if isTCP {
			binary.BigEndian.PutUint32(seg[ipHdrLen+4:ipHdrLen+8], baseSeq+uint32(off))
			f := flags
			if !last {
				f &^= 0x09
			}
			seg[ipHdrLen+13] = f
			writeL4Csum(seg, ipHdrLen, v6, 6)
		} else {
			binary.BigEndian.PutUint16(seg[ipHdrLen+4:ipHdrLen+6], uint16(8+len(chunk)))
			writeL4Csum(seg, ipHdrLen, v6, 17)
		}
		out = append(out, seg)
	}
	return out, true
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
