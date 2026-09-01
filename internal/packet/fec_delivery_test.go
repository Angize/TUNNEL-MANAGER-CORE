package packet

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

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
	time.Sleep(4 * fecFlushDelay)
	mu.Lock()
	wire = append([][]byte(nil), got...)
	mu.Unlock()
	return wire, payloads
}

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

func fecCollect(t *testing.T, n, k int, pkts [][]byte) map[string]int {
	t.Helper()
	seen := map[string]int{}
	d := fecDecoderFor(t, n, k, func(frame []byte) { seen[string(frame)]++ })
	for _, p := range pkts {
		d.input(p)
	}
	return seen
}

func TestFecDeliversTheShardsThatArrived(t *testing.T) {
	wire, payloads := fecEncodeBlock(t, 10, 3, 10)
	data, parity := fecSplit(wire)
	if len(data) != 10 {
		t.Fatalf("encoder emitted %d data shards, want 10", len(data))
	}

	var arrived [][]byte
	lost := map[int]bool{1: true, 4: true, 6: true, 9: true}
	for i, p := range data {
		if !lost[i] {
			arrived = append(arrived, p)
		}
	}
	_ = parity

	seen := fecCollect(t, 10, 3, arrived)
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

func TestFecDeliversWithoutWaitingForTheBlock(t *testing.T) {
	wire, payloads := fecEncodeBlock(t, 10, 3, 10)
	data, _ := fecSplit(wire)

	var got []string
	d := fecDecoderFor(t, 10, 3, func(frame []byte) { got = append(got, string(frame)) })
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
			seen := fecCollect(t, tc.n, tc.k, pkts)
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
