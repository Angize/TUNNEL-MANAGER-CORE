package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// fecBlockOf splits a captured encoder emission stream into the packets of one block id, in the
// order the encoder produced them (data shards first, then parity).
func fecBlockOf(pkts [][]byte, blk uint32) [][]byte {
	var out [][]byte
	for _, p := range pkts {
		if len(p) >= fecHdrLen && binary.BigEndian.Uint32(p[1:5]) == blk {
			out = append(out, p)
		}
	}
	return out
}

// TestFecDeliversAnArrivedShardOverTheByteBudget pins the file-header promise — "nothing a receiver
// physically got is ever held hostage to the rest of its block" — in the one case it used to be
// false: when the decoder's anti-amplification byte budget is exhausted.
//
// A data shard IS its payload (the code is systematic) and deliverShard copies straight out of the
// wire buffer, so handing it on needs no storage at all; only RETAINING it for the RS math does. The
// budget guard sat above the delivery call, so a well-formed shard that physically arrived was
// dropped — with FEC on, tunToNet never writes a frame itself, so the decoder is the only path these
// frames have and that is a hard hole in the stream, with no log, no counter and no event. The
// budget is reachable pre-auth by design (that is what it defends against), which is exactly when
// the real tunnel's own packets must keep flowing.
//
// Everything here goes through the REAL encoder and the REAL input(): the packets are genuine wire
// bytes with genuine RS parity, so the reconstruct at the end really reconstructs. Only the budget
// itself is lowered, so the arithmetic fits in a test instead of 64 MiB of shards.
func TestFecDeliversAnArrivedShardOverTheByteBudget(t *testing.T) {
	var wire [][]byte
	enc, err := newFecEncoder(5, 2, func(p []byte) { wire = append(wire, append([]byte(nil), p...)) })
	if err != nil {
		t.Fatalf("newFecEncoder: %v", err)
	}
	// Every payload is the same size, so every block's shardLen is 98+2 = 100.
	pay := func(tag byte) []byte { return bytes.Repeat([]byte{tag}, 98) }

	// flush ends the block early: n is 5 and no block here carries 5 frames, so without it the
	// encoder would sit on the 15 ms partial-block timer.
	flush := func() { enc.mu.Lock(); enc.flushLocked(); enc.mu.Unlock() }
	// block 0: the filler that will hold the budget down, then be evicted to make room later.
	enc.addData(pay(0xF0))
	flush()
	// block 1: the block under test — three data shards, so it needs parity to complete.
	enc.addData(pay(0xB0))
	enc.addData(pay(0xB1))
	enc.addData(pay(0xB2))
	flush()
	// block 2: its arrival is what triggers the eviction that frees room again.
	enc.addData(pay(0xC0))
	enc.addData(pay(0xC1))
	enc.addData(pay(0xC2))
	flush()

	f, b, c := fecBlockOf(wire, 0), fecBlockOf(wire, 1), fecBlockOf(wire, 2)
	if len(f) < 1 || len(b) < 4 || len(c) < 1 {
		t.Fatalf("encoder emitted %d/%d/%d packets for blocks 0/1/2", len(f), len(b), len(c))
	}

	var got [][]byte
	d := newFecDecoder(func(p []byte) { got = append(got, append([]byte(nil), p...)) })
	// shardLen 100: block 0 reserves (5-1)*100 = 400 pad, blocks 1 and 2 reserve (5-3)*100 = 200.
	// 900 makes block 1's THIRD data shard the first one over the budget.
	d.maxBytes = 900

	d.input(f[0]) // block 0: 400 pad + 100 = 500
	d.input(b[0]) // block 1: +200 pad +100 = 800
	d.input(b[1]) // +100 = 900, exactly at the budget
	d.input(b[2]) // +100 would be 1000: OVER BUDGET — this is the shard the old code threw away
	seenBeforeParity := len(got)

	if seenBeforeParity != 4 {
		t.Fatalf("delivered %d frames, want 4: the shard that arrived while the decoder was over its "+
			"byte budget was dropped even though delivering it needs no storage at all", seenBeforeParity)
	}
	if !bytes.Equal(got[3], pay(0xB2)) {
		t.Fatalf("the 4th delivered frame was %x…, want the over-budget data shard", got[3][:4])
	}

	// Now let the block complete. Block 2's arrival evicts block 0 (oldest by arrival), which frees
	// enough room for block 1's parity to be retained; that is the 5th shard, so it reconstructs.
	d.input(c[0])
	d.input(b[3]) // first parity shard of block 1

	if blk := d.blocks[1]; blk == nil || !blk.done {
		t.Fatalf("block 1 did not reconstruct, so the exactly-once half of this test proved nothing (block=%+v)", blk)
	}
	// deliver's contract is "each sealed frame, exactly once". The recovered-shard loop must skip the
	// slot that was already handed over while over budget, or the peer sees that frame twice — which
	// with crypto off means a duplicate packet injected into the TUN.
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
