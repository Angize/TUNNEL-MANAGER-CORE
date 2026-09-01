package packet

import (
	"bytes"
	"io"
	"testing"
)

// The server sized its upstream reassembly window from `upWorkers` and `maxUpBatch` -- package
// globals that only SetHTTPUpstream writes, and main.go calls that only when role == "client";
// config.go rejects http_up_* on a server outright. So on every server in the fleet the expression
// evaluated to 2*8*128KB = 2 MB, never cleared the 4 MB floor, and the window was a constant 4 MB no
// matter what the operator set on the client.
//
// The client's in-flight is (workers-1) * batch of chunks whose POSTs finished out of order. The
// panel's slider goes to 16 workers and its own default batch is the maximum 512 KB, so at 10
// workers the client can hold 4.5 MB the server refuses: deliver() returns false, the handler answers
// 400, and the client's post worker tears the whole carrier down. Turning the upload knob up made
// uploads impossible, and the default of 8 sat one worker under the cliff.
//
// The expression is now live on the server too: config.go accepted http_up_workers/http_up_batch_kb
// on a CLIENT only, so main.go never called SetHTTPUpstream there and the two globals kept their
// compiled-in 8 and 128 KB. The server now takes the same two knobs -- they describe what its client
// will send, which is exactly what the window has to hold -- and a server nobody configured stays on
// the 4 MB floor, so the memory an unauthenticated attacher can park only grows when the operator
// asked for the throughput.
func TestTheServerWindowHoldsEveryChunkTheClientMaySend(t *testing.T) {
	oldW, oldB := upWorkers, maxUpBatch
	defer SetHTTPUpstream(oldW, oldB>>10, 0)

	if got, want := maxPendBytes(), 4<<20; got != want {
		t.Fatalf("an unconfigured server offers %d bytes, want the %d floor", got, want)
	}

	SetHTTPUpstream(upMaxWorkers, upMaxBatch>>10, 0)
	pr, pw := io.Pipe()
	defer pr.Close()
	go io.Copy(io.Discard, pr)

	q := newReseq(pw, maxPendBytes())
	chunk := bytes.Repeat([]byte{0xA5}, maxUpBatch)

	for seq := uint64(1); seq < uint64(upWorkers); seq++ {
		if !q.deliver(seq, append([]byte(nil), chunk...)) {
			t.Fatalf("the server refused chunk %d of %d while seq 0 was still in flight — %d workers "+
				"times %d KB is what the operator set, and a refusal here is an HTTP 400 that tears "+
				"the carrier down", seq, upWorkers-1, upWorkers, maxUpBatch>>10)
		}
	}
}

// The bound and the clamp have to be the same two numbers, or the next time somebody raises the
// slider the cliff comes back.
func TestTheUpstreamClampCannotOutrunTheWindow(t *testing.T) {
	oldW, oldB := upWorkers, maxUpBatch
	defer SetHTTPUpstream(oldW, oldB>>10, 0)

	SetHTTPUpstream(9999, 9999, 0)
	if upWorkers != upMaxWorkers {
		t.Fatalf("workers clamped to %d, not %d", upWorkers, upMaxWorkers)
	}
	if maxUpBatch != upMaxBatch {
		t.Fatalf("batch clamped to %d, not %d", maxUpBatch, upMaxBatch)
	}
	if inFlight := (upWorkers - 1) * maxUpBatch; inFlight > maxPendBytes() {
		t.Fatalf("the client may hold %d bytes in flight and the server accepts %d", inFlight, maxPendBytes())
	}
}
