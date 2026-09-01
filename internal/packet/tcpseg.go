package packet

import (
	"encoding/binary"
	"net"
)

const (
	tcpPshAck = 0x18
	tcpFin    = 0x01
	tcpSyn    = 0x02
	tcpAckBit = 0x10
	tcpSynAck = 0x12
)

func buildTCPSeg(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, window uint16, opts, payload []byte) []byte {
	if len(opts)%4 != 0 || len(opts) > 40 {
		opts = nil
	}
	hdrLen := 20 + len(opts)
	h := make([]byte, hdrLen+len(payload))
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint32(h[4:8], seq)
	binary.BigEndian.PutUint32(h[8:12], ack)
	h[12] = byte(hdrLen/4) << 4
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:16], window)
	copy(h[20:], opts)
	copy(h[hdrLen:], payload)

	binary.BigEndian.PutUint16(h[16:18], l4Checksum(src, dst, protoTCP, h))
	return h
}
