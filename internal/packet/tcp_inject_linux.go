//go:build linux

package packet

import (
	"log"
	"net"
)

const (
	tcpPshAck = 0x18
	tcpAckBit = 0x10
	tcpSynAck = 0x12
)

func buildTCPSeg(src, dst net.IP, sport, dport uint16, seq, ack uint32, flags byte, window uint16, opts, payload []byte) []byte {
	if len(opts)%4 != 0 || len(opts) > 40 {
		opts = nil
	}
	hdrLen := 20 + len(opts)
	h := make([]byte, hdrLen+len(payload))
	copy(h[20:], opts)
	copy(h[hdrLen:], payload)
	fillTCPSeg(h, hdrLen, src, dst, sport, dport, seq, ack, flags, window)
	return h
}

func (b *TCP) sendTCPFakes(conn net.Conn) {
	if !b.dsOn || conn == nil {
		return
	}
	dst, pkts := b.tcpFakeSegs(conn)
	if len(pkts) == 0 {
		return
	}
	inj, err := newL2Inject()
	if err != nil {
		b.dsSend.failOnce.Do(func() {
			log.Printf("tcp: desync decoys disabled (AF_PACKET: %v) — the carrier needs CAP_NET_RAW", err)
		})
		return
	}
	defer inj.close()
	for _, ip := range pkts {
		b.dsSend.note("tcp", inj.sendTo(dst, ip))
	}
}

func (b *TCP) tcpFakeSegs(conn net.Conn) (net.IP, [][]byte) {
	la, ok1 := conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, nil
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil {
		return nil, nil
	}
	opts, window := tcpDecoyShape(conn)
	d := desyncCfg{on: true, ttl: b.dsTTL, count: b.dsCount, mode: b.dsMode}
	var pkts [][]byte
	for _, sp := range d.specs(false) {
		seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), randUint32(), randUint32(), tcpPshAck, window, opts, fakePayload())
		pkts = append(pkts, buildIP4Ext(src, dst, protoTCP, sp.ttl, sp.badSum, seg))
	}
	return dst, pkts
}
