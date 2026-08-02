package packet

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fecEncodeBlock runs `count` frames through the REAL send path (addData -> fill-flush or the
// fecFlushDelay timer -> emit) and returns the wire packets of the one block it flushed, in emit
// order, plus the payloads that went in. Whatever parity the encoder chose to send is returned
// as-is — no caller here may assume there are k of them.
func fecEncodeBlock(t *testing.T, n, k, count int) (wire, payloads [][]byte) {
	t.Helper()
	var mu sync.Mutex
	var got [][]byte
	e, err := newFecEncoder(n, k, func(p []byte) {
		mu.Lock()
		got = append(got, append([]byte(nil), p...))
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("newFecEncoder(%d,%d): %v", n, k, err)
	}
	defer e.Close()
	for i := 0; i < count; i++ {
		p := []byte(fmt.Sprintf("payload-%03d-of-the-block", i))
		payloads = append(payloads, p)
		e.addData(p)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		seen := len(got)
		mu.Unlock()
		if seen > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a block of %d frames never flushed", count)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(4 * fecFlushDelay) // let the whole flush land before the caller reads it
	mu.Lock()
	wire = append([][]byte(nil), got...)
	mu.Unlock()
	return wire, payloads
}

// fecSplit sorts one block's wire packets into its data shards (indexed by their header idx) and
// its parity shards.
func fecSplit(wire [][]byte) (data, parity [][]byte) {
	for _, p := range wire {
		switch p[0] {
		case fecTypeData:
			data = append(data, p)
		case fecTypeParity:
			parity = append(parity, p)
		}
	}
	return data, parity
}

// fecCollect feeds the given wire packets to a fresh decoder and returns how many times each
// payload was delivered, keyed by the payload text.
func fecCollect(pkts [][]byte) map[string]int {
	seen := map[string]int{}
	d := newFecDecoder(func(frame []byte) { seen[string(frame)]++ })
	for _, p := range pkts {
		d.input(p)
	}
	return seen
}

// TestFecDeliversTheShardsThatArrived: a block that cannot be reconstructed must not throw away the
// intact data shards that DID arrive. With FEC on the decoder is the ONLY path those frames have, so
// losing one shard past the repair budget cost the WHOLE block — at 10+3, ten real packets gone for
// thirteen on the wire, which above ~17% loss makes FEC strictly worse than leaving it off.
func TestFecDeliversTheShardsThatArrived(t *testing.T) {
	wire, payloads := fecEncodeBlock(t, 10, 3, 10)
	data, parity := fecSplit(wire)
	if len(data) != 10 {
		t.Fatalf("encoder emitted %d data shards, want 10", len(data))
	}
	// Lose 4 data shards AND every parity shard: 6 of 13 arrive, far past what 10+3 can repair.
	var arrived [][]byte
	lost := map[int]bool{1: true, 4: true, 6: true, 9: true}
	for i, p := range data {
		if !lost[i] {
			arrived = append(arrived, p)
		}
	}
	_ = parity // deliberately dropped in full

	seen := fecCollect(arrived)
	for i, p := range payloads {
		want := 0
		if !lost[i] {
			want = 1
		}
		if got := seen[string(p)]; got != want {
			t.Fatalf("payload %d delivered %d times, want %d — an unrecoverable block must still "+
				"hand over every data shard that physically arrived", i, got, want)
		}
	}
	if len(seen) != 6 {
		t.Fatalf("delivered %d distinct frames, want the 6 that arrived", len(seen))
	}
}

// TestFecDeliversWithoutWaitingForTheBlock pins the other half of the same property: a data shard
// is handed over as it arrives, not held until its block can be reconstructed. Before, every
// packet of a 10-shard block waited for the tenth — pure added latency even on a lossless link.
func TestFecDeliversWithoutWaitingForTheBlock(t *testing.T) {
	wire, payloads := fecEncodeBlock(t, 10, 3, 10)
	data, _ := fecSplit(wire)

	var got []string
	d := newFecDecoder(func(frame []byte) { got = append(got, string(frame)) })
	d.input(data[0])
	if len(got) != 1 || got[0] != string(payloads[0]) {
		t.Fatalf("after the first data shard the decoder delivered %v, want the first frame — "+
			"an intact shard must not wait for the rest of its block", got)
	}
	d.input(data[1])
	if len(got) != 2 || got[1] != string(payloads[1]) {
		t.Fatalf("after the second data shard the decoder delivered %v, want two frames", got)
	}
}

// TestFecEveryErasurePatternDeliversWhatArrived closes the CLASS rather than one line: for a full 10+3
// block it walks all 2^13 erasure patterns, and for a partial block every pattern over what the encoder
// really emitted. Each must deliver every frame whose own data shard arrived, plus every frame of the
// block once enough shards arrived to reconstruct — each exactly once, and never one it could not know.
func TestFecEveryErasurePatternDeliversWhatArrived(t *testing.T) {
	for _, tc := range []struct{ n, k, count int }{{10, 3, 10}, {10, 3, 4}} {
		wire, payloads := fecEncodeBlock(t, tc.n, tc.k, tc.count)
		data, parity := fecSplit(wire)
		if len(data) != tc.count {
			t.Fatalf("%d+%d count=%d: encoder emitted %d data shards", tc.n, tc.k, tc.count, len(data))
		}
		pads := tc.n - tc.count
		total := len(data) + len(parity)
		for mask := 0; mask < 1<<total; mask++ {
			var pkts [][]byte
			dataPresent, parityPresent := 0, 0
			present := map[int]bool{}
			for i := 0; i < total; i++ {
				if mask&(1<<i) == 0 {
					continue
				}
				if i < len(data) {
					pkts = append(pkts, data[i])
					present[i] = true
					dataPresent++
				} else {
					pkts = append(pkts, parity[i-len(data)])
					parityPresent++
				}
			}
			seen := fecCollect(pkts)
			recoverable := pads+dataPresent+parityPresent >= tc.n
			for i, p := range payloads {
				want := 0
				if present[i] || recoverable {
					want = 1
				}
				if got := seen[string(p)]; got != want {
					t.Fatalf("%d+%d count=%d mask=%0*b (%d data + %d parity arrived, recoverable=%v): "+
						"payload %d delivered %d times, want %d",
						tc.n, tc.k, tc.count, total, mask, dataPresent, parityPresent, recoverable, i, got, want)
				}
			}
			if len(seen) > tc.count {
				t.Fatalf("%d+%d count=%d mask=%0*b: delivered %d distinct frames, more than the block holds",
					tc.n, tc.k, tc.count, total, mask, len(seen))
			}
		}
		t.Logf("%d+%d count=%d: all %d erasure patterns over %d data + %d parity behave",
			tc.n, tc.k, tc.count, 1<<total, len(data), len(parity))
	}
}
