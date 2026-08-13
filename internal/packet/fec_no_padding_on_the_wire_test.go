package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// The encoder pads every shard to the block's LARGEST before handing the block to Reed-Solomon, which
// it must — the codec needs equal lengths. It then used to put the padded copy on the wire. Two costs,
// and the second is the one that matters:
//
//   - a block holding one big packet and nine small ones went out as ten big ones;
//   - every packet of that block left at exactly the same size, which is a shape a real flow does not
//     have and a padding-free tunnel does not have either.
//
// The header already carries shardLen, so the receiver can re-pad. Nothing but the codec needs it.
func TestFecDoesNotPadTheWire(t *testing.T) {
	// One 1400-byte frame and nine 60-byte ones: the mix that shows it.
	sizes := []int{1400, 60, 60, 60, 60, 60, 60, 60, 60, 60}
	frames := make([][]byte, len(sizes))
	for i, n := range sizes {
		frames[i] = bytes.Repeat([]byte{byte('a' + i)}, n)
	}

	sink := &fecCapture{}
	enc, err := newFecEncoder(10, 3, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	sink.reset()
	for _, f := range frames {
		enc.addData(f)
	}
	data, parity := sink.take()
	if len(data) != len(frames) {
		t.Fatalf("%d data shards for %d frames", len(data), len(frames))
	}

	// Every data packet carries its own frame and nothing more.
	shardLen := int(binary.BigEndian.Uint16(data[0][9:11]))
	onWire, padded := 0, 0
	for i, p := range data {
		want := fecHdrLen + 2 + sizes[i] // header + the 2-byte length prefix + the frame
		if len(p) != want {
			t.Errorf("data shard %d is %d bytes on the wire, want %d — it is still carrying %d bytes of padding",
				i, len(p), want, len(p)-want)
		}
		onWire += len(p)
		padded += fecHdrLen + shardLen
	}
	if onWire >= padded {
		t.Errorf("the block cost %d bytes, no better than the %d it cost padded", onWire, padded)
	}
	t.Logf("data shards: %d bytes on the wire, %d if padded", onWire, padded)

	// ...and they are no longer all the same size, which was the tell.
	same := true
	for _, p := range data[1:] {
		if len(p) != len(data[0]) {
			same = false
		}
	}
	if same {
		t.Error("every data packet of the block is still exactly the same size")
	}

	// It still has to WORK: drop two data shards and let parity rebuild them, on a decoder that only
	// ever sees the unpadded wire form.
	var got [][]byte
	dec := newFecDecoder(func(b []byte) { got = append(got, append([]byte(nil), b...)) })
	for i, p := range data {
		if i == 0 || i == 5 { // the big one and a small one
			continue
		}
		dec.input(p)
	}
	for _, p := range parity {
		dec.input(p)
	}
	if len(got) != len(frames) {
		t.Fatalf("%d frames delivered out of %d — a block of mixed sizes no longer reconstructs", len(got), len(frames))
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[string(g)] = true
	}
	for i, f := range frames {
		if !seen[string(f)] {
			t.Errorf("frame %d (%d bytes) came back altered or not at all", i, len(f))
		}
	}
}

// A block whose frames are all the same size must be byte-identical to what it always was: this
// changes what padding is carried, not the framing.
func TestFecUniformBlockIsUnchanged(t *testing.T) {
	sink := &fecCapture{}
	enc, err := newFecEncoder(4, 2, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	sink.reset()
	for i := 0; i < 4; i++ {
		enc.addData([]byte(fmt.Sprintf("frame-%02d-payload", i)))
	}
	data, parity := sink.take()
	if len(data) != 4 || len(parity) != 2 {
		t.Fatalf("got %d data + %d parity", len(data), len(parity))
	}
	shardLen := int(binary.BigEndian.Uint16(data[0][9:11]))
	for i, p := range data {
		if len(p) != fecHdrLen+shardLen {
			t.Errorf("data shard %d is %d bytes, want %d — a uniform block must be exactly what it was",
				i, len(p), fecHdrLen+shardLen)
		}
	}
	for i, p := range parity {
		if len(p) != fecHdrLen+shardLen {
			t.Errorf("parity shard %d is %d bytes, want %d — parity is an OUTPUT of the codec and is always full length",
				i, len(p), fecHdrLen+shardLen)
		}
	}
}

// input() runs pre-auth on attacker-chosen bytes, so the lengths it will accept are a bound, not a
// convenience: a data shard may be shorter than shardLen and never longer, and parity is exact.
func TestFecRefusesAShardThatOverrunsItsBlock(t *testing.T) {
	delivered := 0
	dec := newFecDecoder(func([]byte) { delivered++ })
	mk := func(typ byte, shardLen, bodyLen int) []byte {
		p := make([]byte, fecHdrLen+bodyLen)
		p[0] = typ
		binary.BigEndian.PutUint32(p[1:5], 7)
		p[5], p[6], p[7], p[8] = 0, 4, 2, 4
		binary.BigEndian.PutUint16(p[9:11], uint16(shardLen))
		binary.BigEndian.PutUint16(p[fecHdrLen:], uint16(bodyLen-2)) // the frame's own length prefix
		return p
	}
	for _, tc := range []struct {
		name string
		pkt  []byte
		want int
	}{
		{"a data shard longer than the block's shardLen", mk(fecTypeData, 40, 64), 0},
		{"a parity shard shorter than shardLen", mk(fecTypeParity, 40, 20), 0},
		{"a data shard shorter than shardLen", mk(fecTypeData, 40, 20), 1},
	} {
		delivered = 0
		dec.input(tc.pkt)
		if delivered != tc.want {
			t.Errorf("%s: delivered %d, want %d", tc.name, delivered, tc.want)
		}
	}
}
