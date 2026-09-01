package packet

import (
	"bytes"
	"testing"
)

func fecBlockOf(pkts [][]byte, blk uint32) [][]byte {
	var out [][]byte
	for _, p := range pkts {
		if len(p) >= fecHdrLen && fecHdrPeek(p).blk == blk {
			out = append(out, p)
		}
	}
	return out
}

func TestFecDeliversAnArrivedShardOverTheByteBudget(t *testing.T) {
	var wire [][]byte
	enc, err := newFecEncoder(5, 2, fecTestKey, func(p []byte) { wire = append(wire, append([]byte(nil), p...)) })
	if err != nil {
		t.Fatalf("newFecEncoder: %v", err)
	}

	pay := func(tag byte) []byte { return bytes.Repeat([]byte{tag}, 98) }

	flush := func() { enc.mu.Lock(); enc.flushLocked(); enc.mu.Unlock() }

	enc.addData(pay(0xF0))
	flush()

	enc.addData(pay(0xB0))
	enc.addData(pay(0xB1))
	enc.addData(pay(0xB2))
	flush()

	enc.addData(pay(0xC0))
	enc.addData(pay(0xC1))
	enc.addData(pay(0xC2))
	flush()

	f, b, c := fecBlockOf(wire, 0), fecBlockOf(wire, 1), fecBlockOf(wire, 2)
	if len(f) < 1 || len(b) < 4 || len(c) < 1 {
		t.Fatalf("encoder emitted %d/%d/%d packets for blocks 0/1/2", len(f), len(b), len(c))
	}

	var got [][]byte
	d := fecDecoderFor(t, 5, 2, func(p []byte) { got = append(got, append([]byte(nil), p...)) })

	d.maxBytes = 900

	d.input(f[0])
	d.input(b[0])
	d.input(b[1])
	d.input(b[2])
	seenBeforeParity := len(got)

	if seenBeforeParity != 4 {
		t.Fatalf("delivered %d frames, want 4: the shard that arrived while the decoder was over its "+
			"byte budget was dropped even though delivering it needs no storage at all", seenBeforeParity)
	}
	if !bytes.Equal(got[3], pay(0xB2)) {
		t.Fatalf("the 4th delivered frame was %x…, want the over-budget data shard", got[3][:4])
	}

	d.input(c[0])
	d.input(b[3])

	if blk := d.blocks[1]; blk == nil || !blk.done {
		t.Fatalf("block 1 did not reconstruct, so the exactly-once half of this test proved nothing (block=%+v)", blk)
	}

	dupes := 0
	for _, g := range got {
		if bytes.Equal(g, pay(0xB2)) {
			dupes++
		}
	}
	if dupes != 1 {
		t.Fatalf("the over-budget shard was delivered %d times, want exactly 1 — reconstruct must not "+
			"re-deliver a slot that was already handed on", dupes)
	}
}
