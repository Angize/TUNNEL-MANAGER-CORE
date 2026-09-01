package packet

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var fecTestKey = newFecHdrMask("fec-test-psk")

func fecHdrPeek(p []byte) fecHeader {
	h, _, _ := fecReadHdr(fecTestKey, p)
	return h
}

type fecCapture struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (c *fecCapture) emit(p []byte) {
	c.mu.Lock()
	c.pkts = append(c.pkts, append([]byte(nil), p...))
	c.mu.Unlock()
}

func (c *fecCapture) take() (data, parity [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.pkts {
		switch fecHdrPeek(p).typ {
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
	time.Sleep(4 * fecFlushDelay)
	return sink.take()
}

func TestPartialFecBlockScalesParity(t *testing.T) {
	for _, geo := range []struct{ n, k int }{{10, 3}, {10, 2}, {8, 4}, {4, 1}} {
		sink := &fecCapture{}
		e, err := newFecEncoder(geo.n, geo.k, fecTestKey, sink.emit)
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

			if p*geo.n < geo.k*count {
				t.Fatalf("%d+%d count=%d: %d parity is WEAKER than the configured ratio (needs p*n >= k*count: %d < %d)",
					geo.n, geo.k, count, p, p*geo.n, geo.k*count)
			}

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

func TestPartialFecBlockStillRecoversLoss(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	const count = 4
	data, parity := flushBlock(t, e, sink, count)
	if len(data) != count || len(parity) != 2 {
		t.Fatalf("10+3 count=4: got %d data + %d parity, want 4 + 2", len(data), len(parity))
	}

	for _, p := range append(append([][]byte{}, data...), parity...) {
		if got := fecHdrPeek(p).k; got != 3 {
			t.Fatalf("header k = %d, want the configured 3 — the wire format moved", got)
		}
	}

	var got [][]byte
	d := fecDecoderFor(t, 10, 3, func(frame []byte) { got = append(got, append([]byte(nil), frame...)) })

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

func TestFullFecBlockWireUnchanged(t *testing.T) {
	sink := &fecCapture{}
	e, err := newFecEncoder(10, 3, fecTestKey, sink.emit)
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
			h := fecHdrPeek(p)
			if h.blk != blk {
				t.Fatalf("block id %d, want %d", h.blk, blk)
			}
			if h.idx != wantIdx {
				t.Fatalf("shard %d: idx %d, want %d", i, h.idx, wantIdx)
			}
			if h.n != 10 || h.k != 3 || h.count != 10 {
				t.Fatalf("shard %d: header n,k,count = %d,%d,%d, want 10,3,10", i, h.n, h.k, h.count)
			}
			if h.shardLen != len(p)-fecHdrLen {
				t.Fatalf("shard %d: shardLen %d, body %d", i, h.shardLen, len(p)-fecHdrLen)
			}
		}
	}
}
