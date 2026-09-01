package packet

import (
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// Measured on the netns lab on DE02, one real udp tunnel per row, 20 s of iperf3 TCP over 8 streams
// then 20 s of UDP at 300 Mbit, counting frames that DECRYPTED and were then thrown away by the replay
// guard:
//
//	workers=1   912 Mbit   212167 retransmits         0 replay-rejected
//	workers=2   993 Mbit   236103 retransmits         0 replay-rejected
//	workers=4  1063 Mbit   363852 retransmits    216000 replay-rejected of 2075629 accepted  (9.4%)
//
// One AEAD counter serves the whole tunnel (crypto.Sealer.ctr), and each of the `workers` tunToNet
// goroutines seals frame by frame into its own batch and only then flushes it with one sendmmsg. A
// queue's batch therefore carries sequence numbers spread over as much as workers*maxBatch of the
// shared counter, and the batches reach the wire in whatever order the goroutines finish sealing.
// Anything further behind the newest frame than the window is discarded as a replay -- silently: the
// drop falls through to tryHandshake, so no counter moved and nothing was logged. The panel offers the
// knob as سبک/متوسط/سنگین, which is an invitation to raise it.
//
// The window has to be at least as wide as the reordering the SENDER itself produces. maxWorkers is
// read out of config.go rather than mirrored here, so raising the worker cap without widening the
// window fails this test instead of shipping.
//
// maxWorkers*maxBatch = 256 is the fair-scheduling bound and it is NOT enough. Instrumenting the guard
// on the same lab run and bucketing every out-of-order frame by how far behind the newest it landed:
//
//	64..127   70435      512..1023   5893
//	128..255  59084     1024..2047    107
//	256..511  43346     worst seen   1148
//
// So a 512-wide window still threw away 6000 frames (0.32% of everything received) and only 2048
// covers the tail with margin. That tail is scheduling jitter on a 2-core box under saturation; it has
// no proof behind it, only this measurement, which is why replayDrops logs when the window is ever
// too small again instead of dropping in silence the way this bug did.
func TestTheReplayWindowCoversWhatTheSenderReorders(t *testing.T) {
	const worstMeasured = 1148
	queues := maxWorkersFromConfig(t)
	if replayWindow < queues*maxBatch {
		t.Fatalf("replayWindow %d is under the sender's own worst case: maxWorkers %d * maxBatch %d = %d",
			replayWindow, queues, maxBatch, queues*maxBatch)
	}
	if replayWindow <= worstMeasured {
		t.Fatalf("replayWindow %d is at or under the %d measured on the netns lab at workers=%d",
			replayWindow, worstMeasured, queues)
	}

	for _, workers := range []int{1, 2, queues} {
		batches := make([][]uint64, workers)
		var seq uint64
		for round := 0; round < maxBatch; round++ {
			for q := 0; q < workers; q++ {
				seq++
				batches[q] = append(batches[q], seq)
			}
		}
		orders := [][]int{make([]int, workers), make([]int, workers)}
		for i := 0; i < workers; i++ {
			orders[0][i] = i
			orders[1][i] = workers - 1 - i
		}
		for _, order := range orders {
			var g replayGuard
			rejected := 0
			for _, q := range order {
				for _, s := range batches[q] {
					if !g.ok(1, s) {
						rejected++
					}
				}
			}
			if rejected != 0 {
				t.Errorf("workers=%d flush order %v: %d of %d frames rejected as replays",
					workers, order, rejected, int(seq))
			}
		}
	}
}

func maxWorkersFromConfig(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("../../config.go")
	if err != nil {
		t.Fatalf("reading config.go for maxWorkers: %v", err)
	}
	m := regexp.MustCompile(`(?m)^const maxWorkers = (\d+)$`).FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find `const maxWorkers = N` in config.go; this test can no longer tell " +
			"whether the window still covers the queues")
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil || n < 1 {
		t.Fatalf("maxWorkers parsed as %q", m[1])
	}
	return n
}

// The window is now wider than one word, so the shift that slides it forward is a loop rather than one
// instruction. This holds it against an oracle too dumb to be wrong in the same way.
func TestTheReplayGuardMatchesAnOracle(t *testing.T) {
	type oracle struct {
		top  uint64
		seen map[uint64]bool
		open bool
	}
	oracleOK := func(o *oracle, seq uint64) bool {
		if !o.open {
			o.open, o.top, o.seen = true, seq, map[uint64]bool{seq: true}
			return true
		}
		if seq+replayWindow <= o.top {
			return false
		}
		if o.seen[seq] {
			return false
		}
		o.seen[seq] = true
		if seq > o.top {
			o.top = seq
		}
		return true
	}

	r := rand.New(rand.NewSource(20260901))
	for trial := 0; trial < 200; trial++ {
		var g replayGuard
		o := &oracle{}
		var top uint64 = 1
		for step := 0; step < 4000; step++ {
			var seq uint64
			switch r.Intn(4) {
			case 0:
				seq = top + 1 + uint64(r.Intn(3))
			case 1:
				back := uint64(r.Intn(replayWindow + 40))
				if back > top {
					back = top
				}
				seq = top - back
			case 2:
				seq = top + uint64(r.Intn(2*replayWindow))
			default:
				seq = top
			}
			if seq > top {
				top = seq
			}
			want := oracleOK(o, seq)
			if got := g.ok(7, seq); got != want {
				t.Fatalf("trial %d step %d seq %d: guard said %v, oracle said %v (top %d)",
					trial, step, seq, got, want, top)
			}
		}
	}
}
