package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestFecDoesNotPadTheWire(t *testing.T) {

	sizes := []int{1400, 60, 60, 60, 60, 60, 60, 60, 60, 60}
	frames := make([][]byte, len(sizes))
	for i, n := range sizes {
		frames[i] = bytes.Repeat([]byte{byte('a' + i)}, n)
	}

	sink := &fecCapture{}
	enc, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
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

	shardLen := fecHdrPeek(data[0]).shardLen
	onWire, padded := 0, 0
	for i, p := range data {
		want := fecHdrLen + 2 + sizes[i]
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

	same := true
	for _, p := range data[1:] {
		if len(p) != len(data[0]) {
			same = false
		}
	}
	if same {
		t.Error("every data packet of the block is still exactly the same size")
	}

	var got [][]byte
	dec := fecDecoderFor(t, 10, 3, func(b []byte) { got = append(got, append([]byte(nil), b...)) })
	for i, p := range data {
		if i == 0 || i == 5 {
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

func TestFecUniformBlockIsUnchanged(t *testing.T) {
	sink := &fecCapture{}
	enc, err := newFecEncoder(4, 2, fecTestKey, sink.emit)
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
	shardLen := fecHdrPeek(data[0]).shardLen
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

func TestFecRefusesAShardThatOverrunsItsBlock(t *testing.T) {
	delivered := 0
	dec := fecDecoderFor(t, 4, 2, func([]byte) { delivered++ })
	mk := func(typ byte, shardLen, bodyLen int) []byte {
		body := make([]byte, bodyLen)
		binary.BigEndian.PutUint16(body, uint16(bodyLen-2))
		return fecPutHdr(fecTestKey, fecHeader{typ: typ, blk: 7, n: 4, k: 2, count: 4, shardLen: shardLen}, body)
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
