//go:build linux

// TCP-segment injection desync for the kernel-socket TCP-family carriers (tcp / cover / ws). The real
// connection stays kernel-owned; right after it connects we inject a few DECOY TCP segments on its exact
// 4-tuple, wrapped in a low-TTL IPv4 header and pushed at L2 via AF_PACKET. A stateful DPI ingests them
// and mis-syncs, while the decoys expire before the server so the kernel's TCP is untouched.
package packet

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
)

// sendTCPFakes injects the configured decoy segments on conn's 4-tuple just after connect. Best-effort:
// httpc's synthetic conn fails the *net.TCPAddr assertion and is skipped, and a missing CAP_NET_RAW or an
// unresolvable next hop just drops the decoys. One-shot per connect, when the next-hop neighbour is
// guaranteed warm — the kernel has just completed the three-way handshake through it.
func (b *TCP) sendTCPFakes(conn net.Conn) {
	if b.dsWatch != nil {
		b.dsWatch(conn) // test seam; see the field comment. Before the dsOn gate on purpose.
	}
	if !b.dsOn || conn == nil {
		return
	}
	la, ok1 := conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return // synthetic addrs (httpc) — no real 4-tuple to mirror
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil {
		return // an IPv6 4-tuple — the raw IPv4 injector can't mirror it
	}
	inj, err := newL2Inject()
	if err != nil {
		b.dsFailOnce.Do(func() {
			log.Printf("tcp: desync decoys disabled (AF_PACKET: %v) — the carrier needs CAP_NET_RAW", err)
		})
		return
	}
	defer inj.close()
	d := newDesyncCfg(b.dsOn, b.dsTTL, b.dsCount, b.dsMode)
	for _, sp := range d.specsTCP() {
		seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), randSeq32(), randSeq32(), tcpPshAck, 0xffff, fakePayload())
		if ip := buildIP4Ext(src, dst, protoTCP, sp.ttl, sp.badSum, seg); ip != nil {
			b.dsSend.note("tcp", inj.sendTo(dst, ip))
		}
	}
}

// randSeq32 returns a random 32-bit value for a decoy segment's sequence/ack fields.
func randSeq32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
