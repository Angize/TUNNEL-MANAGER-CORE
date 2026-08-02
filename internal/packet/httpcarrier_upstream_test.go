package packet

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The http carrier's upstream is a request/response ladder: capacity is (in-flight bytes)/RTT, while
// anything merely QUEUED is pure added latency a keepalive ping cannot jump — the obfs length-mask
// keystream forbids reordering, so there is no priority lane. Those two are easy to conflate, and this
// pins the shape so a small in-flight window behind a deep waiting queue cannot come back.
func TestUpstreamSizingInvariants(t *testing.T) {
	inFlight := upWorkers * maxUpBatch
	waiting := upChanCap*1400 + upWorkCap*maxUpBatch

	// Capacity: at a CDN-ish 150 ms round-trip the window has to be worth tens of Mbit, or the
	// carrier itself becomes the bottleneck and the inner TCP never gets to see the real path.
	if got := float64(inFlight) * 8 / 0.150 / 1e6; got < 40 {
		t.Errorf("in-flight window %d B ⇒ only %.1f Mbit at a 150ms RTT; want >= 40", inFlight, got)
	}
	// Latency: the queue in front of the window is what a ping waits behind. Keep it to roughly one
	// batch, not a reservoir — this is the half that made the operator's ping jump under load.
	if waiting > 3*maxUpBatch {
		t.Errorf("waiting queue %d B is more than 3 batches (%d B): that is standing latency, not buffer",
			waiting, 3*maxUpBatch)
	}
	// The write channel must be able to hold one whole batch: the batcher only coalesces what is
	// ALREADY queued, so a channel smaller than a batch silently caps the batch size — measured 6.3
	// Mbit instead of 29.7 when this was set to 16.
	if upChanCap*1400 < maxUpBatch {
		t.Errorf("upChanCap %d chunks (%d B) cannot hold one %d B batch, so batches stay small",
			upChanCap, upChanCap*1400, maxUpBatch)
	}
	// A batch must fit the server's per-POST read cap, or the server truncates and drops it.
	if maxUpBatch >= maxPostBody {
		t.Errorf("maxUpBatch %d must stay under maxPostBody %d", maxUpBatch, maxPostBody)
	}
	// Fewer idle conns than workers means a finished POST's connection is closed rather than kept,
	// so the next POST pays a fresh TCP+TLS handshake through the CDN. +1 for the streaming GET.
	if upIdleConns < upWorkers+1 {
		t.Errorf("upIdleConns %d < upWorkers+1 %d: POSTs will re-handshake", upIdleConns, upWorkers+1)
	}
	// Parallel requests are also a fingerprint: a browser opens a handful to one host, not dozens.
	if upWorkers > 12 {
		t.Errorf("upWorkers %d is more parallel requests than a browser plausibly opens", upWorkers)
	}
	// The default must stay the Cloudflare shape: unpaced. A CDN that needs pacing asks for it.
	if upMinGap != 0 {
		t.Errorf("upMinGap defaults to %v; the compiled-in profile must not throttle", upMinGap)
	}
}

// The shape is per-CDN now, so the setter has to actually move all of it — and clamp, because these
// numbers reach the core straight from an operator field. A batch over the server's per-POST read cap
// would be truncated, and a truncated length-prefixed AEAD chunk desyncs the stream.
func TestSetHTTPCUpstream(t *testing.T) {
	w0, b0, c0, i0, g0 := upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap
	defer func() { upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap = w0, b0, c0, i0, g0 }()

	SetHTTPUpstream(0, 0, 0)
	if upWorkers != w0 || maxUpBatch != b0 || upMinGap != g0 {
		t.Fatalf("all-zero must leave the defaults alone, got %d/%d/%v", upWorkers, maxUpBatch, upMinGap)
	}

	SetHTTPUpstream(4, 512, 30) // the measured ArvanCloud profile
	if upWorkers != 4 || maxUpBatch != 512<<10 {
		t.Errorf("workers/batch not applied: %d/%d", upWorkers, maxUpBatch)
	}
	if upChanCap*1400 < maxUpBatch {
		t.Errorf("upChanCap %d was not recomputed for the new batch, so batches would stay small", upChanCap)
	}
	if upIdleConns < upWorkers+1 {
		t.Errorf("upIdleConns %d not recomputed: POSTs would re-handshake", upIdleConns)
	}
	if want := time.Second / 30; upMinGap != want {
		t.Errorf("upMinGap %v, want %v (30 POSTs/sec)", upMinGap, want)
	}

	SetHTTPUpstream(999, 99999, 99999)
	if upWorkers != 16 {
		t.Errorf("workers not clamped: %d", upWorkers)
	}
	if maxUpBatch != 512<<10 || maxUpBatch >= maxPostBody {
		t.Errorf("batch not clamped under the server read cap: %d (cap %d)", maxUpBatch, maxPostBody)
	}
	if upMinGap != time.Second/1000 {
		t.Errorf("rate not clamped: %v", upMinGap)
	}
}

// Pacing must cost nothing when the link is idle — the gap only ever applies to a dispatch that
// FOLLOWS a recent one. A cap that also delayed the first packet would put a fixed tax on every
// interactive round-trip.
func TestUpMinGapPacesBurstsButNotAnIdleLink(t *testing.T) {
	g0 := upMinGap
	defer func() { upMinGap = g0 }()
	upMinGap = 60 * time.Millisecond

	r := newUpRecorder(0)
	u, failed, done := startUp(t, r)
	defer done()

	t0 := time.Now()
	if _, err := u.write(make([]byte, 100), 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	r.waitPosts(t, 1, 3*time.Second)
	if d := time.Since(t0); d > 40*time.Millisecond {
		t.Errorf("the first POST on an idle link waited %v; pacing must not delay it", d)
	}

	// Now a burst. The clock starts BEFORE the writes: write() blocks on the queue, so the pacing is
	// paid during the loop — timing only the wait afterwards measures nothing.
	t1 := time.Now()
	for i := 0; i < 400; i++ {
		if _, err := u.write(make([]byte, 1400), 0); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	r.waitPosts(t, 5, 10*time.Second)
	if d := time.Since(t1); d < 3*upMinGap {
		t.Errorf("5 batches went out in %v, under the %v the rate cap requires — pacing is not applied",
			d, 3*upMinGap)
	}
	if failed() {
		t.Error("the upstream reported a POST failure")
	}
}

// upRecorder is a fake edge that records each POST's seq and body.
type upRecorder struct {
	mu     sync.Mutex
	got    map[uint64][]byte
	order  []uint64
	live   int
	peak   int
	delay  time.Duration
	notify chan struct{}
}

func newUpRecorder(delay time.Duration) *upRecorder {
	return &upRecorder{got: map[uint64][]byte{}, delay: delay, notify: make(chan struct{}, 4096)}
}

func (r *upRecorder) handler(w http.ResponseWriter, req *http.Request) {
	seq, _ := strconv.ParseUint(req.URL.Query().Get("seq"), 10, 64)
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.live++
	if r.live > r.peak {
		r.peak = r.live
	}
	r.mu.Unlock()
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	r.live--
	r.got[seq] = body
	r.order = append(r.order, seq)
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *upRecorder) waitPosts(t *testing.T, n int, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		r.mu.Lock()
		have := len(r.got)
		r.mu.Unlock()
		if have >= n {
			return
		}
		select {
		case <-r.notify:
		case <-deadline:
			t.Fatalf("only %d of %d POSTs arrived in %v", have, n, d)
		}
	}
}

// startUp returns the upstream, a "did a POST fail yet" probe, and a teardown. The probe is separate
// from teardown on purpose: cancelling the context legitimately fails whatever POSTs are still in
// flight, so asserting after teardown would flag every test that ends with a busy pipeline.
func startUp(t *testing.T, r *upRecorder) (*httpcUp, func() bool, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(r.handler))
	ctx, cancel := context.WithCancel(context.Background())
	var failed atomic.Bool
	u := newHTTPCUp(ctx, srv.Client(),
		func(seq uint64) string { return srv.URL + "/?s=x&seq=" + strconv.FormatUint(seq, 10) },
		func(*http.Request) {},
		func() { failed.Store(true) })
	return u, failed.Load, func() { cancel(); srv.Close() }
}

// An idle link must post the moment it has something, not wait to fill a batch — the batcher blocks
// for the FIRST chunk and then drains only what is already queued. If that ever became "wait for
// maxUpBatch", every interactive packet would pay up to a full batch of delay.
func TestXhUpPostsSmallWriteImmediately(t *testing.T) {
	r := newUpRecorder(0)
	u, failed, done := startUp(t, r)
	defer done()

	small := make([]byte, 100)
	for i := range small {
		small[i] = byte(i)
	}
	if _, err := u.write(small, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	r.waitPosts(t, 1, 3*time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got[0]) != 100 {
		t.Fatalf("first POST carried %d bytes, want the 100 written (a batch was not padded/held)", len(r.got[0]))
	}
	if failed() {
		t.Error("the upstream reported a POST failure")
	}
}

// A burst must coalesce into batches that actually use the window, and the byte stream must survive
// reassembly in the WORST order — which is what several workers racing through a CDN produces.
func TestXhUpCoalescesAndReassemblesOutOfOrder(t *testing.T) {
	r := newUpRecorder(25 * time.Millisecond) // a slow edge, so the queue builds and batches grow
	u, failed, done := startUp(t, r)
	defer done()

	const chunks, chunkLen = 300, 1400
	want := make([]byte, 0, chunks*chunkLen)
	for i := 0; i < chunks; i++ {
		c := make([]byte, chunkLen)
		for j := range c {
			c[j] = byte(i + j)
		}
		if _, err := u.write(c, 0); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		want = append(want, c...)
	}

	// wait until every written byte has been POSTed
	deadline := time.After(20 * time.Second)
	for {
		r.mu.Lock()
		total := 0
		for _, b := range r.got {
			total += len(b)
		}
		n := len(r.got)
		r.mu.Unlock()
		if total >= len(want) {
			t.Logf("%d chunks (%d B) went out in %d POSTs", chunks, len(want), n)
			break
		}
		select {
		case <-r.notify:
		case <-deadline:
			t.Fatalf("only %d of %d bytes posted", total, len(want))
		}
	}

	if failed() {
		t.Fatal("the upstream reported a POST failure while still sending")
	}

	r.mu.Lock()
	seqs := make([]uint64, 0, len(r.got))
	maxBody := 0
	for s, b := range r.got {
		seqs = append(seqs, s)
		if len(b) > maxBody {
			maxBody = len(b)
		}
		if len(b) > maxUpBatch {
			r.mu.Unlock()
			t.Fatalf("POST seq %d carried %d bytes, over the %d cap the server will read", s, len(b), maxUpBatch)
		}
	}
	got := make(map[uint64][]byte, len(r.got))
	for s, b := range r.got {
		got[s] = b
	}
	r.mu.Unlock()

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, s := range seqs {
		if s != uint64(i) {
			t.Fatalf("seq %d missing (got %v): the server stalls at the first gap", i, seqs)
		}
	}
	if len(seqs) >= chunks {
		t.Fatalf("%d POSTs for %d chunks — nothing coalesced", len(seqs), chunks)
	}
	// The point of the window: batches must be able to exceed the old 32 KiB cap, which is what made
	// the upstream a 4.4 Mbit bottleneck.
	if maxBody <= 32<<10 {
		t.Errorf("largest batch was %d B; with a slow edge and %d queued chunks it should exceed 32 KiB",
			maxBody, chunks)
	}

	// Now reassemble exactly the way the server does, but hand the chunks over in REVERSE seq order —
	// the pathological case for the in-order buffer that concurrent workers make routine.
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}),
		pend: map[uint64][]byte{}}
	var out []byte
	var rerr error
	readDone := make(chan struct{})
	go func() {
		out, rerr = io.ReadAll(pr)
		close(readDone)
	}()
	go func() {
		for i := len(seqs) - 1; i >= 0; i-- {
			s.deliver(seqs[i], got[seqs[i]])
		}
		pw.Close()
	}()
	select {
	case <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("reassembly never completed")
	}
	if rerr != nil {
		t.Fatalf("reassembly read: %v", rerr)
	}
	if string(out) != string(want) {
		t.Fatalf("reassembled %d bytes, want %d — the upstream byte stream did not survive reordering",
			len(out), len(want))
	}
}

// The worker count has to actually take effect: a stale literal loop bound would leave the window at
// a fraction of upWorkers × maxUpBatch while every constant still read correctly.
func TestXhUpPostsInParallel(t *testing.T) {
	r := newUpRecorder(150 * time.Millisecond) // long enough that several POSTs overlap
	u, failed, done := startUp(t, r)
	defer done()

	// enough bytes to need many batches at the new size (200 chunks is only ~3), or the workers never
	// have anything to overlap on and this measures nothing.
	chunks := 20 * (maxUpBatch / 1400)
	for i := 0; i < chunks; i++ {
		c := make([]byte, 1400)
		if _, err := u.write(c, 0); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	r.waitPosts(t, 8, 30*time.Second)

	r.mu.Lock()
	peak := r.peak
	r.mu.Unlock()
	if failed() {
		t.Fatal("the upstream reported a POST failure while still sending")
	}
	if peak < upWorkers/2 {
		t.Errorf("peak concurrent POSTs was %d; with %d workers and a slow edge it should be much higher "+
			"(is the worker loop still using a literal?)", peak, upWorkers)
	}
	t.Logf("peak concurrent POSTs: %d (upWorkers=%d)", peak, upWorkers)
}
