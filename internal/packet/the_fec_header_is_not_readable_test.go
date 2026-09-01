package packet

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func fecWireOf(t *testing.T, psk string, blocks, count, size int) [][]byte {
	t.Helper()
	var wire [][]byte
	enc, _ := newFecPair(true, 10, 3, psk, "hdr-test",
		func(p []byte) { wire = append(wire, append([]byte(nil), p...)) }, func([]byte) {})
	if enc == nil {
		t.Fatal("no encoder")
	}
	defer enc.Close()
	rng := rand.New(rand.NewSource(7))
	for b := 0; b < blocks; b++ {
		for i := 0; i < count; i++ {
			f := make([]byte, size)
			rng.Read(f)
			enc.addData(f)
		}
		if count < 10 {
			enc.mu.Lock()
			enc.flushLocked()
			enc.mu.Unlock()
		}
	}
	return wire
}

// Before this change the header was written in the clear ahead of the ciphertext, so with the shipped
// 10+3 preset byte 6 of every datagram was literally 0x0A and byte 7 was 0x03, on every packet of
// every Angize FEC tunnel on the internet, and bytes 1..4 were a counter that went up by one per
// block. Measured on the unfixed tree: 13 of 13 packets carried 0x0A at byte 6 and 0x03 at byte 7,
// and byte 0 took exactly the 2 values fecTypeData / fecTypeParity.
//
// The header is now XORed with a chacha20 keystream keyed off the PSK, with the shard body as the
// nonce, so no wire byte of it is a function of the configuration any more.
func TestTheFecHeaderIsNotReadableOnTheWire(t *testing.T) {
	wire := fecWireOf(t, "a-psk-for-the-header", 200, 10, 400)
	if len(wire) != 200*13 {
		t.Fatalf("emitted %d packets, want %d", len(wire), 200*13)
	}
	for pos := 0; pos < fecHdrLen; pos++ {
		seen := map[byte]bool{}
		for _, p := range wire {
			seen[p[pos]] = true
		}
		if len(seen) < 200 {
			t.Errorf("wire byte %d takes only %d distinct values over %d packets — it still leaks the header",
				pos, len(seen), len(wire))
		}
	}
	for i := 1; i < 13; i++ {
		if bytes.Equal(wire[0][:fecHdrLen], wire[i][:fecHdrLen]) {
			t.Fatalf("shards 0 and %d of one block share their masked header", i)
		}
	}
	t.Logf("%d packets: every header byte position takes >=200 distinct values", len(wire))
}

// Two tunnels with different PSKs must not be able to read each other's headers, or the mask is a
// fixed obfuscation rather than a key.
func TestTheFecHeaderMaskIsKeyed(t *testing.T) {
	wire := fecWireOf(t, "psk-one", 1, 10, 300)
	other := newFecHdrMask("psk-two")
	accepted := 0
	for _, p := range wire {
		h, _, _ := fecReadHdr(other, p)
		if h.typ == fecTypeData || h.typ == fecTypeParity {
			if h.n == 10 && h.k == 3 {
				accepted++
			}
		}
	}
	if accepted != 0 {
		t.Fatalf("%d of %d shards parsed as our geometry under the wrong key", accepted, len(wire))
	}
}

// The block id is 4 bytes of the header and it used to be plaintext, so an on-path injector read the
// current value, wrote blk+1 with any geometry it liked, and the first shard to arrive DEFINED the
// block: every genuine shard that followed disagreed and was dropped at the mismatch check, before
// the delivery call. Measured on the unfixed tree: one 13-byte packet cost 10 of 10 real frames.
//
// Two things had to change. The header is keyed, so an attacker cannot name a block at all; and a
// shard that disagrees with the block it lands in is still handed up, because a data shard carries
// its own length and its own AEAD and needs nothing from the block to be delivered.
func TestAForgedFecShardCannotBlackholeABlock(t *testing.T) {
	const psk = "a-psk-for-the-injector"
	wire := fecWireOf(t, psk, 1, 10, 250)

	var got [][]byte
	_, dec := newFecPair(true, 10, 3, psk, "victim", func([]byte) {},
		func(f []byte) { got = append(got, append([]byte(nil), f...)) })

	clear := make([]byte, fecHdrLen+2)
	clear[0] = fecTypeData
	binary.BigEndian.PutUint32(clear[1:5], 0)
	clear[6], clear[7], clear[8] = 10, 3, 1
	binary.BigEndian.PutUint16(clear[9:11], 2)
	dec.input(clear)

	rng := rand.New(rand.NewSource(1))
	forged := 0
	for i := 0; i < 200000; i++ {
		p := make([]byte, fecHdrLen+2+rng.Intn(64))
		rng.Read(p)
		before := len(dec.blocks)
		dec.input(p)
		if len(dec.blocks) != before {
			forged++
		}
	}
	if forged != 0 {
		t.Errorf("%d of 200000 random packets were accepted as a header", forged)
	}

	delivered := 0
	for _, p := range wire {
		before := len(got)
		dec.input(p)
		if len(got) > before {
			delivered++
		}
	}
	if delivered != 10 {
		t.Fatalf("the injection cost %d of 10 frames; on the unfixed tree it cost all 10", 10-delivered)
	}
	t.Logf("one plaintext-header injection plus 200000 random packets: %d blocks of state, %d of 10 frames delivered",
		len(dec.blocks), delivered)
}

// The same guarantee stated without an attacker, because the block id is not bound to the session:
// when a peer restarts its counter goes back to 0 while the receiver still holds blocks 0..63, so a
// genuine new shard lands in a stale block of a different shape. Dropping it there would lose real
// payload for a whole keepalive interval.
func TestAShardThatDisagreesWithItsBlockIsStillDelivered(t *testing.T) {
	const psk = "a-psk-for-the-restart"
	old := fecWireOf(t, psk, 1, 3, 120)
	fresh := fecWireOf(t, psk, 1, 10, 900)

	var got [][]byte
	_, dec := newFecPair(true, 10, 3, psk, "victim", func([]byte) {},
		func(f []byte) { got = append(got, append([]byte(nil), f...)) })

	key := newFecHdrMask(psk)
	if a, b := fecHdrOfKey(key, old[0]), fecHdrOfKey(key, fresh[0]); a.blk != b.blk {
		t.Fatalf("setup: the two encoders started at blocks %d and %d", a.blk, b.blk)
	}
	for _, p := range old {
		dec.input(p)
	}
	before := len(got)
	data := 0
	for _, p := range fresh {
		if fecHdrOfKey(key, p).typ != fecTypeData {
			continue
		}
		data++
		dec.input(p)
	}
	if data != 10 {
		t.Fatalf("setup: %d data shards", data)
	}
	if n := len(got) - before; n != 10 {
		t.Fatalf("after the peer restarted its block counter, %d of 10 data shards were delivered", n)
	}
}

func fecHdrOfKey(key fecHdrMask, p []byte) fecHeader {
	h, _, _ := fecReadHdr(key, p)
	return h
}

// A pass frame carries a control message and has no block, so its header is all zeros under the mask
// and every one of those 80 bits is checked on the way in. That is what keeps a forged packet from
// being handed straight to the crypto layer as a control frame.
func TestAPassFrameCarriesAnAllZeroHeader(t *testing.T) {
	const psk = "a-psk-for-pass"
	var got [][]byte
	enc, dec := newFecPair(true, 10, 3, psk, "pass", func([]byte) {},
		func(f []byte) { got = append(got, append([]byte(nil), f...)) })
	defer enc.Close()

	body := []byte("a-control-frame-that-must-survive")
	p := fecTag(enc, body)
	if len(p) != fecHdrLen+len(body) {
		t.Fatalf("a pass frame is %d bytes for a %d-byte body", len(p), len(body))
	}
	dec.input(p)
	if len(got) != 1 || !bytes.Equal(got[0], body) {
		t.Fatalf("the control frame did not round-trip: %q", got)
	}

	key := newFecHdrMask(psk)
	for _, bad := range []fecHeader{
		{typ: fecTypePass, blk: 1},
		{typ: fecTypePass, idx: 1},
		{typ: fecTypePass, n: 10},
		{typ: fecTypePass, k: 3},
		{typ: fecTypePass, count: 1},
		{typ: fecTypePass, shardLen: 2},
	} {
		got = nil
		dec.input(fecPutHdr(key, bad, body))
		if len(got) != 0 {
			t.Errorf("a pass frame with %+v was accepted", bad)
		}
	}
}
