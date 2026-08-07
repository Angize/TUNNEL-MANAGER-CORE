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

// tcpFakeSegs builds the decoy IPv4 packets for conn's 4-tuple — one per configured spec, each a PSH|ACK
// segment carrying the SAME TCP options and advertised window the connection's real segments carry, so
// the decoys are not separable on header shape. Returns no packets when there is no real IPv4 4-tuple to
// mirror, which is also why it runs before the AF_PACKET socket is opened. The shape is read once: real
// segments sent back-to-back share a timestamp and a window, so the decoys of one burst must too.
func (b *TCP) tcpFakeSegs(conn net.Conn) (net.IP, [][]byte) {
	la, ok1 := conn.LocalAddr().(*net.TCPAddr)
	ra, ok2 := conn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, nil // synthetic addrs (httpc) — no real 4-tuple to mirror
	}
	src, dst := la.IP.To4(), ra.IP.To4()
	if src == nil || dst == nil {
		return nil, nil // an IPv6 4-tuple — the raw IPv4 injector can't mirror it
	}
	opts, window := tcpDecoyShape(conn)
	d := newDesyncCfg(b.dsOn, b.dsTTL, b.dsCount, b.dsMode)
	body := b.decoyBody()
	var pkts [][]byte
	for _, sp := range d.specsTCP() {
		seg := buildTCPSeg(src, dst, uint16(la.Port), uint16(ra.Port), randSeq32(), randSeq32(), tcpPshAck, window, opts, body())
		if ip := buildIP4Ext(src, dst, protoTCP, sp.ttl, sp.badSum, seg); ip != nil {
			pkts = append(pkts, ip)
		}
	}
	return dst, pkts
}

// decoyBody picks what a decoy segment carries, which has to be whatever the REAL segments of this
// carrier carry. On tcp and on plain ws the real bytes are AEAD ciphertext, so fakePayload's random bytes
// already match. On a cover or wss carrier every real byte is a TLS record, and there a decoy of bare
// random bytes is the one thing on the 4-tuple that could not be a record at all -- which makes the
// INJECTION identifiable, whatever it does to the DPI's reassembly.
func (b *TCP) decoyBody() func() []byte {
	if b.cover || (b.ws && b.wsTLS) {
		return tlsRecordPayload
	}
	return fakePayload
}

// tlsRecordPayload wraps random bytes in a well-formed TLS application_data record. application_data is
// opaque by design, so one carrying random bytes is indistinguishable from every other record in the
// flow -- which is the point, since the decoy is the only segment here that is not one.
func tlsRecordPayload() []byte {
	body := fakePayload()[5:] // keep the segment the same size on the wire as the bare form
	rec := make([]byte, 5+len(body))
	rec[0], rec[1], rec[2] = 0x17, 0x03, 0x03 // application_data, TLS 1.2 legacy record version
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(body)))
	copy(rec[5:], body)
	return rec
}

// randSeq32 returns a random 32-bit value for a decoy segment's sequence/ack fields.
func randSeq32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}
