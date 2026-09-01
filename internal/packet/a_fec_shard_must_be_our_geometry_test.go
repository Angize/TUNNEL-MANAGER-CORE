package packet

import (
	"fmt"
	"testing"
	"time"
)

func fecDecoderFor(t *testing.T, n, k int, deliver func([]byte)) *fecDecoder {
	t.Helper()
	c, err := newFECCodec(n, k)
	if err != nil {
		t.Fatalf("newFECCodec(%d,%d): %v", n, k, err)
	}
	return newFecDecoder(c, fecTestKey, deliver)
}

func fecDataShard(blk uint32, n, k int) []byte {
	return fecPutHdr(fecTestKey, fecHeader{typ: fecTypeData, blk: blk, n: n, k: k, count: 1, shardLen: 2}, make([]byte, 2))
}

// The decoder used to take its geometry off the wire: bytes 6 and 7 of an unauthenticated packet
// picked n and k, range-checked only against 1..255 with n+k<=256 and never against what this tunnel
// was configured for. udp.go hands every datagram from any source to fecDec.input before a byte is
// authenticated, so anyone who could reach the port chose the size of the matrix the receiver would
// invert, and did it holding both the decoder mutex and the receive mutex.
//
// Measured on DE02 before the fix: 255 packets, 3315 wire bytes, one 255x255 GF(256) inversion in
// 387us -- about 14.6x more CPU time than it takes to put those bytes on a 1 Gbit link. Sweeping 80
// distinct geometries cost 249 KB for 20 ms. The old defence was an LRU cache of codecs, which kept
// the cost of each SIZE down but not the cost of using it.
//
// Both ends are configured together, so a shard that is not our geometry is not ours. Refusing it up
// front makes the codec a fixed, single, configured object and takes the choice away from the wire.
func TestAFecShardMustBeOurGeometry(t *testing.T) {
	var wire [][]byte
	e, err := newFecEncoder(10, 3, fecTestKey, func(p []byte) { wire = append(wire, append([]byte(nil), p...)) })
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 10)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("real-payload-%02d", i))
		e.addData(payloads[i])
	}
	e.Close()
	if len(wire) != 13 {
		t.Fatalf("encoder emitted %d packets, want 13 (one 10+3 block)", len(wire))
	}

	seen := map[string]int{}
	d := fecDecoderFor(t, 10, 3, func(frame []byte) { seen[string(frame)]++ })

	blk := uint32(1000)
	sprayed := 0
	for n := 2; n <= 255; n++ {
		for k := 1; k <= 255 && n+k <= 256; k++ {
			if n == 10 && k == 3 {
				continue
			}
			d.input(fecDataShard(blk, n, k))
			blk++
			sprayed++
		}
	}
	if sprayed < 1000 {
		t.Fatalf("setup: only %d foreign geometries sprayed", sprayed)
	}
	d.mu.Lock()
	blocks, bytes := len(d.blocks), d.bytes
	d.mu.Unlock()
	if blocks != 0 || bytes != 0 {
		t.Fatalf("%d foreign-geometry shards left %d blocks and %d bytes of state; a shard that is not "+
			"our geometry must be refused before anything is allocated for it", sprayed, blocks, bytes)
	}

	for _, p := range wire {
		if h := fecHdrPeek(p); h.typ == fecTypeData && h.idx == 3 {
			continue
		}
		d.input(p)
	}
	for i := range payloads {
		if got := seen[string(payloads[i])]; got != 1 {
			t.Fatalf("payload %d delivered %d times, want 1 -- the spray broke real recovery", i, got)
		}
	}
}

// The cost of one hostile block, so the number in the commit message stays honest. The geometry check
// means the whole 255-packet sequence is now refused at the header, and the only work left is parsing
// eleven bytes each.
func TestAHostileFecBlockCostsNothing(t *testing.T) {
	d := fecDecoderFor(t, 10, 3, func([]byte) {})
	const n, k, count, shardLen = 255, 1, 255, 2
	mk := func(typ byte, idx int) []byte {
		return fecPutHdr(fecTestKey, fecHeader{typ: typ, blk: 7, idx: idx, n: n, k: k, count: count, shardLen: shardLen}, make([]byte, shardLen))
	}
	var pkts [][]byte
	for i := 0; i < count-1; i++ {
		pkts = append(pkts, mk(fecTypeData, i))
	}
	pkts = append(pkts, mk(fecTypeParity, 0))

	start := time.Now()
	for _, p := range pkts {
		d.input(p)
	}
	el := time.Since(start)
	t.Logf("255 hostile packets, %d wire bytes, %v", len(pkts)*(fecHdrLen+shardLen), el)
	if el > time.Millisecond {
		t.Errorf("a hostile block still cost %v; it was 387us of GF(256) inversion before the geometry "+
			"check and should now be one AES block to unmask the header plus eleven bytes of parsing "+
			"(about 110us for these 255 packets, four times that under -race)", el)
	}
}

// A short block pads up to n on the receiver. Those pad shards are all zero and identical, so they are
// one buffer pointed at from every pad slot rather than n-count separate allocations: 13 bytes of wire
// used to buy (n-count)*shardLen of memory, up to 4 MB at the geometries the wire could ask for.
// Reconstruct only ever reads them, and nothing below count is ever a pad, so the sharing is invisible.
func TestAShortFecBlockSharesOnePadBuffer(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	const count = 4
	data, parity := flushBlock(t, e, sink, count)

	var got [][]byte
	d := fecDecoderFor(t, 10, 3, func(f []byte) { got = append(got, append([]byte(nil), f...)) })
	for i, p := range data {
		if i == 1 {
			continue
		}
		d.input(p)
	}
	for _, p := range parity {
		d.input(p)
	}

	d.mu.Lock()
	b := d.blocks[fecHdrPeek(data[0]).blk]
	d.mu.Unlock()
	if b == nil {
		t.Fatal("the block is gone")
	}
	first := b.shards[count]
	for i := count; i < 10; i++ {
		if &b.shards[i][0] != &first[0] {
			t.Fatalf("pad slot %d has its own allocation", i)
		}
	}
	if len(got) != count {
		t.Fatalf("the block delivered %d frames, want %d -- recovery broke", len(got), count)
	}

	lone := fecDecoderFor(t, 10, 3, func([]byte) {})
	lone.input(data[0])
	lone.mu.Lock()
	only := lone.blocks[fecHdrPeek(data[0]).blk]
	total, shardLen := lone.bytes, only.shardLen
	lone.mu.Unlock()
	if want := 2 * shardLen; total != want {
		t.Errorf("one data shard of a %d-of-10 block charges %d bytes, want %d (the shard plus ONE "+
			"shared pad buffer); the old code charged %d for the padding alone",
			count, total, want, (10-count)*shardLen)
	}
}
