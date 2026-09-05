package packet

import (
	"net"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// What reading the destination costs, now that the pool owns it.
//
// The carrier used to keep the address in its own atomic and the pool kept a cursor; the two could
// disagree, and the "pin" existed to reconcile them. The carrier now reads the pool's published
// address on the send path instead. Three things were measured before choosing that:
//
//   - the old cached read: one atomic load
//   - taking the pool's mutex and walking its health set per packet: ~21ns settled, ~33ns mid-rotation
//   - re-parsing the pool's STRING back into an address per packet: 174ns, 48 B/op, 2 allocs/op
//
// So the pool pre-builds the address form once, at construction, and publishes a pointer to it. The
// read is an atomic load and a branch, next to a per-packet path that costs ~1700ns of AEAD. These
// benchmarks are the receipt: run them next to BenchmarkPacketPath* and the share is the throughput.

func benchPool(n int) *PeerPool {
	addrs := make([]string, n)
	for i := range addrs {
		addrs[i] = "203.0.113." + string(rune('0'+i%10)) + ":9000"
	}
	return NewPeerPool(addrs, 0)
}

func benchSealer(b *testing.B) Sealer {
	s, err := crypto.NewSealer("aes-256-gcm", "a-sufficiently-long-preshared-key", true)
	if err != nil {
		b.Skipf("no sealer: %v", err)
	}
	return s
}

const benchMTU = 1400

// the destination read on its own, with a pool: what ships
func BenchmarkDstFromPool(b *testing.B) {
	r := &Raw{isClient: true, pp: benchPool(8)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.dst() == nil {
			b.Fatal("nil")
		}
	}
}

// and without one, which is the carrier's own atomic — the read this replaced
func BenchmarkDstFromOwnPeer(b *testing.B) {
	r := &Raw{}
	r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(203, 0, 113, 7)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.dst() == nil {
			b.Fatal("nil")
		}
	}
}

// the same two next to the per-packet work the carrier does anyway, which is what decides the design
func BenchmarkPacketPathPooled(b *testing.B) {
	sb := benchSealer(b)
	r := &Raw{isClient: true, pp: benchPool(8)}
	payload := make([]byte, benchMTU)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.dst() == nil {
			b.Fatal("nil")
		}
		if _, err := sealBody(sb, false, typeData, payload, padMaxFor(typeData)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPacketPathUnpooled(b *testing.B) {
	sb := benchSealer(b)
	r := &Raw{}
	r.soloPeer.Store(&net.IPAddr{IP: net.IPv4(203, 0, 113, 7)})
	payload := make([]byte, benchMTU)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r.dst() == nil {
			b.Fatal("nil")
		}
		if _, err := sealBody(sb, false, typeData, payload, padMaxFor(typeData)); err != nil {
			b.Fatal(err)
		}
	}
}

// the two rejected shapes, kept so nobody has to re-derive why the pool pre-builds the form
func BenchmarkRejectedLockedPoolRead(b *testing.B) {
	p := benchPool(8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p.current() == "" {
			b.Fatal("empty")
		}
	}
}

func BenchmarkRejectedParsePerPacket(b *testing.B) {
	s := "203.0.113.7:9000"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip := parseIP4(hostOnly(s)); ip == nil {
			b.Fatal("nil")
		}
	}
}
