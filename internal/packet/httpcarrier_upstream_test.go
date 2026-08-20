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

func TestUpstreamSizingInvariants(t *testing.T) {
	inFlight := upWorkers * maxUpBatch
	waiting := upChanCap*1400 + upWorkCap*maxUpBatch

	if got := float64(inFlight) * 8 / 0.150 / 1e6; got < 40 {
		t.Errorf("in-flight window %d B ⇒ only %.1f Mbit at a 150ms RTT; want >= 40", inFlight, got)
	}

	if waiting > 3*maxUpBatch {
		t.Errorf("waiting queue %d B is more than 3 batches (%d B): that is standing latency, not buffer",
			waiting, 3*maxUpBatch)
	}

	if upChanCap*1400 < maxUpBatch {
		t.Errorf("upChanCap %d chunks (%d B) cannot hold one %d B batch, so batches stay small",
			upChanCap, upChanCap*1400, maxUpBatch)
	}

	if maxUpBatch >= maxPostBody {
		t.Errorf("maxUpBatch %d must stay under maxPostBody %d", maxUpBatch, maxPostBody)
	}

	if upIdleConns < upWorkers+1 {
		t.Errorf("upIdleConns %d < upWorkers+1 %d: POSTs will re-handshake", upIdleConns, upWorkers+1)
	}

	if upWorkers > 12 {
		t.Errorf("upWorkers %d is more parallel requests than a browser plausibly opens", upWorkers)
	}

	if upMinGap != 0 {
		t.Errorf("upMinGap defaults to %v; the compiled-in profile must not throttle", upMinGap)
	}
}

func TestSetHTTPCUpstream(t *testing.T) {
	w0, b0, c0, i0, g0 := upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap
	defer func() { upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap = w0, b0, c0, i0, g0 }()

	SetHTTPUpstream(0, 0, 0)
	if upWorkers != w0 || maxUpBatch != b0 || upMinGap != g0 {
		t.Fatalf("all-zero must leave the defaults alone, got %d/%d/%v", upWorkers, maxUpBatch, upMinGap)
	}

	SetHTTPUpstream(4, 512, 30)
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

func TestXhUpCoalescesAndReassemblesOutOfOrder(t *testing.T) {
	r := newUpRecorder(25 * time.Millisecond)
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

	if maxBody <= 32<<10 {
		t.Errorf("largest batch was %d B; with a slow edge and %d queued chunks it should exceed 32 KiB",
			maxBody, chunks)
	}

	s := newHTTPCSession()
	pr, pw := s.upR, s.upW
	var out []byte
	var rerr error
	readDone := make(chan struct{})
	go func() {
		out, rerr = io.ReadAll(pr)
		close(readDone)
	}()
	go func() {
		for i := len(seqs) - 1; i >= 0; i-- {
			s.up.deliver(seqs[i], got[seqs[i]])
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

func TestXhUpPostsInParallel(t *testing.T) {
	r := newUpRecorder(150 * time.Millisecond)
	u, failed, done := startUp(t, r)
	defer done()

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
