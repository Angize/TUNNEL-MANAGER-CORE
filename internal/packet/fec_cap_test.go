package packet

import (
	"encoding/binary"
	"testing"
)

func fecDataShard(blk uint32, n, k int) []byte {
	pkt := make([]byte, fecHdrLen+2)
	pkt[0] = fecTypeData
	binary.BigEndian.PutUint32(pkt[1:5], blk)
	pkt[5] = 0
	pkt[6] = byte(n)
	pkt[7] = byte(k)
	pkt[8] = 1
	binary.BigEndian.PutUint16(pkt[9:11], 2)
	return pkt
}

func TestFecDecoderCodecCap(t *testing.T) {
	d := newFecDecoder(func([]byte) {})
	blk := uint32(0)

	for n := 2; n <= 250; n++ {
		for k := 1; k <= 250 && n+k <= 256; k++ {
			d.input(fecDataShard(blk, n, k))
			blk++
			if blk > 4000 {
				break
			}
		}
		if blk > 4000 {
			break
		}
	}
	d.mu.Lock()
	got := len(d.codecs)
	d.mu.Unlock()
	if got > fecMaxCodecs {
		t.Fatalf("fecDecoder.codecs grew to %d past the cap %d — pre-auth memory-exhaustion DoS not bounded", got, fecMaxCodecs)
	}
	t.Logf("fec codec cap held: %d distinct (n,k) geometries sprayed, codecs cache bounded at %d (cap %d)", blk, got, fecMaxCodecs)
}
