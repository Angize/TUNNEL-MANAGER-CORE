package packet

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestFecCodecCacheCannotBePoisoned(t *testing.T) {

	var wire [][]byte
	e, err := newFecEncoder(10, 3, func(p []byte) { wire = append(wire, append([]byte(nil), p...)) })
	if err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 20)
	for i := range payloads {
		payloads[i] = []byte(fmt.Sprintf("real-payload-%02d", i))
		e.addData(payloads[i])
	}
	e.Close()
	if len(wire) != 26 {
		t.Fatalf("encoder emitted %d packets, want 26 (two 10+3 blocks)", len(wire))
	}

	seen := map[string]int{}
	d := newFecDecoder(func(frame []byte) { seen[string(frame)]++ })

	spray := func(firstBlk uint32) {
		blk := firstBlk
		for n := 100; n < 100+2*fecMaxCodecs; n++ {
			d.input(fecDataShard(blk, n, 7))
			blk++
		}
	}

	feedBlockLosing := func(blk uint32, lose int) {
		for _, p := range wire {
			if binary.BigEndian.Uint32(p[1:5]) != blk {
				continue
			}
			if p[0] == fecTypeData && int(p[5]) == lose {
				continue
			}
			d.input(p)
		}
	}

	spray(1000)
	feedBlockLosing(0, 3)
	if got := seen[string(payloads[3])]; got != 1 {
		t.Fatalf("after a %d-geometry spray, the lost frame of a real 10+3 block was recovered %d times, want 1 — "+
			"the codec cache was poisoned and FEC recovery is silently dead", 2*fecMaxCodecs, got)
	}
	for i := 0; i < 10; i++ {
		if got := seen[string(payloads[i])]; got != 1 {
			t.Fatalf("block 0: payload %d delivered %d times, want 1", i, got)
		}
	}

	spray(2000)
	feedBlockLosing(1, 7)
	for i := 10; i < 20; i++ {
		if got := seen[string(payloads[i])]; got != 1 {
			t.Fatalf("block 1 after a second spray: payload %d delivered %d times, want 1 — "+
				"the live geometry did not survive being evicted and re-learned", i, got)
		}
	}

	d.mu.Lock()
	n := len(d.codecs)
	d.mu.Unlock()
	if n > fecMaxCodecs {
		t.Fatalf("codec cache grew to %d past the cap %d — the pre-auth memory bound is gone", n, fecMaxCodecs)
	}
}

func TestFecCodecCacheEvictsLeastRecentlyUsed(t *testing.T) {
	d := newFecDecoder(func([]byte) {})
	blk := uint32(0)
	use := func(n, k int) {
		d.input(fecDataShard(blk, n, k))
		blk++
	}

	live := 40
	use(live, 3)
	for i := 0; i < fecMaxCodecs-1; i++ {
		use(100+i, 7)
		use(live, 3)
	}
	d.mu.Lock()
	full := len(d.codecs)
	d.mu.Unlock()
	if full != fecMaxCodecs {
		t.Fatalf("cache holds %d codecs, want it filled to the cap %d", full, fecMaxCodecs)
	}

	use(200, 9)
	d.mu.Lock()
	_, liveKept := d.codecs[live<<8|3]
	_, coldGone := d.codecs[100<<8|7]
	n := len(d.codecs)
	d.mu.Unlock()
	if n > fecMaxCodecs {
		t.Fatalf("cache grew to %d past the cap %d", n, fecMaxCodecs)
	}
	if !liveKept {
		t.Fatalf("the most-recently-used geometry was evicted — eviction is not LRU")
	}
	if coldGone {
		t.Fatalf("the least-recently-used geometry survived — nothing was evicted to make room, so a full " +
			"cache still refuses every new geometry and stays poisoned")
	}
}
