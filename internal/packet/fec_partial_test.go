package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fecCapture collects the wire packets an encoder emits. emit runs with the encoder's own
// mutex held, so the capture keeps a lock of its own and never calls back into the encoder.
type fecCapture struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *fecCapture) emit(p []byte) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), p...))
	c.mu.Unlock()
}

// take returns a snapshot of the packets captured so far, split by wire type.
func (c *fecCapture) take() (data, parity [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pkts {
		switch p[0] {
		case fecTypeData:
			data = append(data, p)
		case fecTypeParity:
			parity = append(parity, p)
		}
	}
	return data, parity
}

func (c *fecCapture) reset() {
	c.mu.Lock()
	c.pkts = nil
	c.mu.Unlock()
}

// flushBlock feeds `count` distinct sealed frames through the REAL send path (addData) and
// waits for the block to reach the wire — either the fill-flush at count==n or, below that,
// the fecFlushDelay timer. It then waits one more grace period so a test that asserts "no
// more than X parity" cannot pass by reading the emit loop mid-flight.
func flushBlock(t *testing.T, e *fecEncoder, sink *fecCapture, count int) (data, parity [][]byte) {
	t.Helper()
	sink.reset()
	for i := 0; i < count; i++ {
		e.addData([]byte(fmt.Sprintf("frame-%02d-payload", i)))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if d, _ := sink.take(); len(d) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("block of %d never flushed within 5s", count)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(4 * fecFlushDelay) // let every shard of the flush land, and any stray extra
	return sink.take()
}

// TestPartialFecBlockScalesParity: a partial block must scale its parity count with the data shards it
// really carries, not emit the full k. The test pins the property, not the formula — the parity emitted
// must still hold the configured erasure ratio and be the smallest count that does, and one fewer must
// break it. Together those fix the value uniquely, so neither a regression to k nor a cut to zero passes.
func TestPartialFecBlockScalesParity(t *testing.T) {
	for _, geo := range []struct{ n, k int }{{10, 3}, {10, 2}, {8, 4}, {4, 1}} {
		sink := &fecCapture{}
		e, err := newFecEncoder(geo.n, geo.k, sink.emit)
		if err != nil {
			t.Fatalf("newFecEncoder(%d,%d): %v", geo.n, geo.k, err)
		}
		for count := 1; count <= geo.n; count++ {
			data, parity := flushBlock(t, e, sink, count)
			p := len(parity)
			if len(data) != count {
				t.Fatalf("%d+%d count=%d: emitted %d data shards, want %d", geo.n, geo.k, count, len(data), count)
			}
			if p < 1 {
				t.Fatalf("%d+%d count=%d: emitted no parity at all — the block has no protection", geo.n, geo.k, count)
			}
			// (a) protection held: p/(count+p) >= k/(n+k), cross-multiplied to exact integers.
			if p*geo.n < geo.k*count {
				t.Fatalf("%d+%d count=%d: %d parity is WEAKER than the configured ratio (needs p*n >= k*count: %d < %d)",
					geo.n, geo.k, count, p, p*geo.n, geo.k*count)
			}
			// (b) and not one shard more than that: p-1 must break (a).
			if (p-1)*geo.n >= geo.k*count {
				t.Fatalf("%d+%d count=%d: %d parity is MORE than the configured ratio needs (%d would still hold it) — %.0f%% overhead instead of %.0f%%",
					geo.n, geo.k, count, p, p-1, 100*float64(p)/float64(count), 100*float64(geo.k)/float64(geo.n))
			}
			if count == geo.n && p != geo.k {
				t.Fatalf("%d+%d count=%d: a FULL block must still emit all %d parity, got %d", geo.n, geo.k, count, geo.k, p)
			}
		}
		e.Close()
	}
}

// TestPartialFecBlockStillRecoversLoss proves the scaled parity is real protection and not just cheaper:
// a 4-frame flush of a 10+3 tunnel goes out as 4 data + 2 parity, and losing TWO of the four data shards
// must still deliver all four frames. It also pins that this is not a wire change — the shards go to an
// UNMODIFIED decoder, which copes because the header still declares k and the missing parity is an erasure.
func TestPartialFecBlockStillRecoversLoss(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	const count = 4
	data, parity := flushBlock(t, e, sink, count)
	if len(data) != count || len(parity) != 2 {
		t.Fatalf("10+3 count=4: got %d data + %d parity, want 4 + 2", len(data), len(parity))
	}
	// The header must still carry the CONFIGURED k, or a decoder would size the block wrong.
	for _, p := range append(append([][]byte{}, data...), parity...) {
		if got := int(p[7]); got != 3 {
			t.Fatalf("header k = %d, want the configured 3 — the wire format moved", got)
		}
	}

	var got [][]byte
	d := newFecDecoder(func(frame []byte) { got = append(got, append([]byte(nil), frame...)) })
	// Lose data shards 1 and 3 — the worst the 2 emitted parity shards can repair.
	for i, p := range data {
		if i == 1 || i == 3 {
			continue
		}
		d.input(p)
	}
	for _, p := range parity {
		d.input(p)
	}
	if len(got) != count {
		t.Fatalf("recovered %d frames, want %d — the scaled parity did not repair the loss it must", len(got), count)
	}
	// Every frame of the block, each exactly once. The SEQUENCE is deliberately not asserted:
	// when a shard reaches the carrier is the decoder's business (an intact shard may be handed
	// over as it arrives, ahead of one that parity still has to rebuild), and it is not what
	// scaling the parity count is about.
	seen := map[string]int{}
	for _, frame := range got {
		seen[string(frame)]++
	}
	for i := 0; i < count; i++ {
		want := fmt.Sprintf("frame-%02d-payload", i)
		if seen[want] != 1 {
			t.Fatalf("frame %d delivered %d times, want exactly 1", i, seen[want])
		}
	}
}

// TestFullFecBlockWireUnchanged pins that a saturated tunnel — the case the geometry was chosen
// for — emits exactly what it always did: n data shards then k parity, in index order, all one
// shardLen, with the block counter advancing by one.
func TestFullFecBlockWireUnchanged(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for blk := uint32(0); blk < 3; blk++ {
		data, parity := flushBlock(t, e, sink, 10)
		if len(data) != 10 || len(parity) != 3 {
			t.Fatalf("block %d: got %d data + %d parity, want 10 + 3", blk, len(data), len(parity))
		}
		for i, p := range append(append([][]byte{}, data...), parity...) {
			wantIdx := i
			if i >= 10 {
				wantIdx = i - 10
			}
			if got := binary.BigEndian.Uint32(p[1:5]); got != blk {
				t.Fatalf("block id %d, want %d", got, blk)
			}
			if int(p[5]) != wantIdx {
				t.Fatalf("shard %d: idx %d, want %d", i, p[5], wantIdx)
			}
			if int(p[6]) != 10 || int(p[7]) != 3 || int(p[8]) != 10 {
				t.Fatalf("shard %d: header n,k,count = %d,%d,%d, want 10,3,10", i, p[6], p[7], p[8])
			}
			if got := int(binary.BigEndian.Uint16(p[9:11])); got != len(p)-fecHdrLen {
				t.Fatalf("shard %d: shardLen %d, body %d", i, got, len(p)-fecHdrLen)
			}
		}
	}
}
