//go:build linux

package packet

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
)

func (b *TCP) sendTCPFakes(conn net.Conn) {
	if b.dsWatch != nil {
		b.dsWatch(conn)
	}
	if !b.dsOn || conn == nil {
		return
	}
	dst, pkts := b.tcpFakeSegs(conn)
	if len(pkts) == 0 {
		return
	}
	inj, err := newL2Inject()
	if err != nil {
		b.dsFailOnce.Do(func() {
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
	d := newDesyncCfg(b.dsOn, b.dsTTL, b.dsCount, b.dsMode)
	var pkts [][]byte
	for _, sp := range d.specsTCP() {
		seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), randSeq32(), randSeq32(), tcpPshAck, window, opts, fakePayload())
		if ip := buildIP4Ext(src, dst, protoTCP, sp.ttl, sp.badSum, seg); ip != nil {
			pkts = append(pkts, ip)
		}
	}
	return dst, pkts
}

func randSeq32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
