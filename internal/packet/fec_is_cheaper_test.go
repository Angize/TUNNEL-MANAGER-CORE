package packet

import (
	"bytes"
	"testing"
)

// The multiplication table replaced a per-byte gmul(): two branches and three table reads became one
// indexed load from a 256-byte row that stays in L1. It is only an optimisation if it computes the
// same field, so this checks every entry rather than a sample.
func TestTheMultiplicationTableIsTheSameField(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := gfMul[a][b], gmul(byte(a), byte(b)); got != want {
				t.Fatalf("gfMul[%d][%d] = %d, the field says %d", a, b, got, want)
			}
		}
	}
	dst := make([]byte, 64)
	src := make([]byte, 64)
	for i := range src {
		src[i] = byte(i * 7)
		dst[i] = byte(255 - i)
	}
	want := append([]byte(nil), dst...)
	for i := range want {
		want[i] ^= gmul(0x53, src[i])
	}
	gfMulAddRow(dst, src, 0x53)
	if !bytes.Equal(dst, want) {
		t.Fatal("gfMulAddRow does not agree with the field it replaced")
	}

	zero := make([]byte, 8)
	keep := append([]byte(nil), zero...)
	gfMulAddRow(zero, src[:8], 0)
	if !bytes.Equal(zero, keep) {
		t.Error("multiplying by zero changed the row")
	}
}

// A block used to leave as n+k separate emits, and on raw that was n+k separate sendto syscalls --
// thirteen for a 10/3 block. The encoder hands the whole block over in one call now so the carrier
// can put it in one sendmmsg. Measured on DE02: FEC went 257 -> 320 Mbit with the table and
// 320 -> 397 with this.
func TestABlockLeavesTheEncoderInOneCall(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 10; i++ {
		e.addData([]byte("a-frame-that-fills-one-tenth-of-a-block"))
	}
	sink.mu.Lock()
	blocks, pkts := sink.blocks, len(sink.pkts)
	sink.mu.Unlock()
	if blocks != 1 {
		t.Errorf("a full block took %d emits; the carrier can only batch what it is handed at once", blocks)
	}
	if pkts != 13 {
		t.Errorf("the block carried %d shards, want 10 data + 3 parity", pkts)
	}
}

// A partial block -- the timer fired before n frames arrived -- must still leave in one call, with
// the parity count scaled to what was actually queued.
func TestAPartialBlockAlsoLeavesInOneCall(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i := 0; i < 4; i++ {
		e.addData([]byte("short-block"))
	}
	e.mu.Lock()
	e.flushLocked()
	e.mu.Unlock()
	sink.mu.Lock()
	blocks, pkts := sink.blocks, len(sink.pkts)
	sink.mu.Unlock()
	if blocks != 1 {
		t.Errorf("a partial block took %d emits", blocks)
	}
	if pkts != 6 {
		t.Errorf("a 4-frame block carried %d shards, want 4 data + 2 parity", pkts)
	}
}

// Nothing above is worth anything if the block no longer repairs. This is the property, end to end:
// drop as many shards as the geometry allows and every frame must still come out.
//
// ORDER IS NOT PART OF THE CONTRACT and asserting it would be asserting a bug. The decoder hands over
// what arrived as it arrives and the reconstructed shards afterwards, so a block that lost its first
// three data shards delivers frames 3..9 first and then 0..2. The tunnel carries TCP, which reorders
// anyway, and the replay window is sized for it.
func TestTheBlockStillRepairsWhatItIsMeantTo(t *testing.T) {
	for _, geo := range []struct{ n, k int }{{10, 3}, {20, 4}, {4, 2}} {
		sink := &fecCapture{}
		e, err := newFecEncoder(geo.n, geo.k, fecTestKey, sink.emit)
		if err != nil {
			t.Fatal(err)
		}
		var got [][]byte
		d := newFecDecoder(e.codec, fecTestKey, func(f []byte) { got = append(got, append([]byte(nil), f...)) })
		var want [][]byte
		for i := 0; i < geo.n; i++ {
			f := []byte{byte(i), byte(i + 1), byte(i + 2), 'x', 'y', 'z'}
			want = append(want, f)
			e.addData(f)
		}
		sink.mu.Lock()
		wire := append([][]byte(nil), sink.pkts...)
		sink.mu.Unlock()
		e.Close()
		if len(wire) != geo.n+geo.k {
			t.Fatalf("%d+%d: %d shards on the wire", geo.n, geo.k, len(wire))
		}
		for i := 0; i < geo.k; i++ {
			wire[i] = nil
		}
		for _, w := range wire {
			if w != nil {
				d.input(w)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%d+%d: %d of %d frames came out after losing %d shards",
				geo.n, geo.k, len(got), len(want), geo.k)
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				if bytes.Equal(g, w) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%d+%d: frame %v never came out, so the repair lost it", geo.n, geo.k, w)
			}
		}
	}
}
