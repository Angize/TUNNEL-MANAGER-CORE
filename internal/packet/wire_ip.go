package packet

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"
)

const ipFlagDF = 1 << 14

var ipIDCounter atomic.Uint32

func init() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	ipIDCounter.Store(binary.BigEndian.Uint32(b[:]))
}

func nextIPID() uint16 {
	if id := uint16(ipIDCounter.Add(1)); id != 0 {
		return id
	}
	return uint16(ipIDCounter.Add(1))
}

func buildIP4Ext(src, dst net.IP, proto, ttl int, badSum bool, payload []byte) []byte {
	if len(payload) > 0xffff-20 {
		return nil
	}
	if ttl < 1 {
		ttl = 1
	} else if ttl > 255 {
		ttl = 255
	}
	h := make([]byte, 20+len(payload))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))

	binary.BigEndian.PutUint16(h[4:6], nextIPID())
	binary.BigEndian.PutUint16(h[6:8], ipFlagDF)
	h[8] = byte(ttl)
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	sum := onesComplementSum(h[:20])
	binary.BigEndian.PutUint16(h[10:12], sum)
	if badSum {
		binary.BigEndian.PutUint16(h[10:12], ^sum)
		if onesComplementSum(h[:20]) == 0 {
			binary.BigEndian.PutUint16(h[10:12], ^sum^0x0001)
		}
	}
	copy(h[20:], payload)
	return h
}

func sumBytes(b []byte) uint32 {
	var sum uint64
	for len(b) >= 8 {
		v := binary.BigEndian.Uint64(b)
		sum += v >> 48
		sum += (v >> 32) & 0xffff
		sum += (v >> 16) & 0xffff
		sum += v & 0xffff
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

func foldComplement(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func onesComplementSum(b []byte) uint16 {
	return foldComplement(sumBytes(b))
}

func l4Checksum(src, dst net.IP, proto int, l4 []byte) uint16 {
	s, d := src.To4(), dst.To4()
	var ph [12]byte
	if s != nil {
		copy(ph[0:4], s)
	}
	if d != nil {
		copy(ph[4:8], d)
	}
	ph[9] = byte(proto)
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(l4)))
	return foldComplement(sumBytes(ph[:]) + sumBytes(l4))
}
