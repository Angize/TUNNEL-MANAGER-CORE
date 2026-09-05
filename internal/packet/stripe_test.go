package packet

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Counts, per request, whether that response carried any bytes: how many streams the download actually
// spread over, rather than how many the client opened.
type streamCounter struct {
	http.ResponseWriter
	wrote *bool
}

func (c streamCounter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		*c.wrote = true
	}
	return c.ResponseWriter.Write(p)
}

func (c streamCounter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c streamCounter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type downHarness struct {
	srv    *httptest.Server
	b      *TCP
	inFlgt atomic.Int64
	refuse atomic.Int64
	tries  atomic.Int64
	cutIdx string
	cut    atomic.Int64
	cutHit atomic.Int64
	mu     sync.Mutex
	used   []*bool
}

// A response that stops accepting bytes part-way, the way a stream does when its connection goes.
type cutWriter struct {
	http.ResponseWriter
	left *atomic.Int64
	hit  *atomic.Int64
}

func (c cutWriter) Write(p []byte) (int, error) {
	if c.left.Add(-int64(len(p))) < 0 {
		c.hit.Add(1)
		return 0, errors.New("the stream went away mid-write")
	}
	return c.ResponseWriter.Write(p)
}

func (c cutWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c cutWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *downHarness) carried() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, w := range h.used {
		if *w {
			n++
		}
	}
	return n
}

// A server whose http carrier is real: the handler, the session, and the queue are the production
// ones. handleServerConn parks on the upstream pipe because no POST ever arrives, which is what keeps
// the session open for the test.
func newDownHarness(t *testing.T) *downHarness {
	t.Helper()
	h := &downHarness{b: &TCP{
		ws: true, httpc: true, idle: connIdle, ping: pingEvery,
		preAuth: make(chan struct{}, maxPreAuthConns), httpcSessions: make(map[string]*httpcSession),
	}}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("d") != "0" {
			h.tries.Add(1)
			if h.refuse.Load() > 0 {
				h.refuse.Add(-1)
				http.Error(w, "", http.StatusServiceUnavailable)
				return
			}
		}
		wrote := new(bool)
		h.mu.Lock()
		h.used = append(h.used, wrote)
		h.mu.Unlock()
		h.inFlgt.Add(1)
		defer h.inFlgt.Add(-1)
		var rw http.ResponseWriter = streamCounter{ResponseWriter: w, wrote: wrote}
		if h.cutIdx != "" && r.URL.Query().Get("d") == h.cutIdx {
			rw = cutWriter{ResponseWriter: rw, left: &h.cut, hit: &h.cutHit}
		}
		h.b.httpcHandler(rw, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *downHarness) session(t *testing.T, d time.Duration) *httpcSession {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		h.b.httpcMu.Lock()
		for _, s := range h.b.httpcSessions {
			h.b.httpcMu.Unlock()
			return s
		}
		h.b.httpcMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no session was created by the download GETs")
	return nil
}

// Waits until n streams have reached the server. dialHTTPCPost opens stream 0 before it returns and
// the rest in goroutines, so a test that writes as soon as it has a session is racing them -- and a
// test that then counts how many streams carried is measuring the dial, not the striping.
func (h *downHarness) waitStreams(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for h.inFlgt.Load() < int64(n) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := h.inFlgt.Load(); got < int64(n) {
		t.Fatalf("only %d of %d streams reached the server", got, n)
	}
}

// Dials the carrier the way the client really does, with n download streams.
func dialDown(t *testing.T, h *downHarness, n int) (net.Conn, func()) {
	t.Helper()
	old := carrierStreams
	carrierStreams = n
	t.Cleanup(func() { carrierStreams = old })

	cl := &TCP{}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := cl.dialHTTPCPost(h.srv.Client(), func() {}, ctx, cancel,
		h.srv.URL+"/", randSID(), "test-edge", func(*http.Request) {}, 2*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	return conn, func() { conn.Close(); cancel() }
}

func TestADownloadArrivesWholeAndInOrderAcrossItsStreams(t *testing.T) {
	h := newDownHarness(t)
	conn, done := dialDown(t, h, 4)
	defer done()

	s := h.session(t, 3*time.Second)
	h.waitStreams(t, 4)

	const chunks, chunkLen = 400, 1400
	want := make([]byte, 0, chunks*chunkLen)
	go func() {
		for i := 0; i < chunks; i++ {
			c := make([]byte, chunkLen)
			for j := range c {
				c[j] = byte(i*7 + j)
			}
			if _, err := s.down.write(c, 0); err != nil {
				return
			}
		}
	}()
	for i := 0; i < chunks; i++ {
		c := make([]byte, chunkLen)
		for j := range c {
			c[j] = byte(i*7 + j)
		}
		want = append(want, c...)
	}

	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for off := 0; off < len(got); off += chunkLen * 10 {
		end := off + chunkLen*10
		if end > len(got) {
			end = len(got)
		}
		if _, err := io.ReadFull(conn, got[off:end]); err != nil {
			t.Fatalf("read back: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("the stream diverges at byte %d of %d: the records were reassembled out of order",
					i, len(want))
			}
		}
	}
	if n := h.carried(); n < 2 {
		t.Fatalf("only %d of 4 streams carried any bytes: the download is still single-file and the "+
			"knob is decoration", n)
	}
}

func TestOneDownloadStreamIsStillAWholeCarrier(t *testing.T) {
	h := newDownHarness(t)
	conn, done := dialDown(t, h, 1)
	defer done()
	s := h.session(t, 3*time.Second)

	msg := []byte("a single stream must carry the whole tunnel")
	if _, err := s.down.write(msg, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
	if n := h.carried(); n != 1 {
		t.Fatalf("%d streams carried bytes for a one-stream carrier", n)
	}
}

func TestASessionThatEndsEndsTheCarrier(t *testing.T) {
	h := newDownHarness(t)
	conn, done := dialDown(t, h, 3)
	defer done()
	s := h.session(t, 3*time.Second)

	// Ending the SESSION ends every stream at once and there is nothing left to reopen. A single
	// stream dying is a different matter — see the cut-stream test below.
	s.close(h.b, func() string {
		h.b.httpcMu.Lock()
		defer h.b.httpcMu.Unlock()
		for sid := range h.b.httpcSessions {
			return sid
		}
		return ""
	}())

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("a read succeeded after every download stream ended: the carrier hides a hole it can never fill")
	}
}

func TestTheServerBoundsAStreamThatStopsBeingRead(t *testing.T) {
	h := newDownHarness(t)

	// A raw GET whose body is never read: the server must not park a stream writer on it forever.
	req, err := http.NewRequest("GET", h.srv.URL+"/?s="+randSID()+"&d=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	s := h.session(t, 3*time.Second)
	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		big := make([]byte, 256<<10)
		for i := 0; i < 512; i++ {
			if _, err := s.down.write(big, time.Now().Add(2*time.Second).UnixNano()); err != nil {
				return
			}
		}
	}()
	select {
	case <-blocked:
	case <-time.After(30 * time.Second):
		t.Fatal("writing to a stream nobody reads never returned: the goroutine draining the TUN is held forever")
	}
}

func TestAnOversizeRecordEndsTheStreamInsteadOfBeingAllocated(t *testing.T) {
	var hdr [recHdr]byte
	binary.BigEndian.PutUint64(hdr[0:8], 0)
	binary.BigEndian.PutUint32(hdr[8:12], maxRecord+1)

	pr, pw := io.Pipe()
	defer pr.Close()
	q := newReseq(pw, maxStripePend(1))
	failed := make(chan struct{})
	go readStripe(io.NopCloser(bytes.NewReader(hdr[:])), q, func() { close(failed) })

	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		t.Fatalf("a record claiming %d bytes was accepted; the reader must refuse anything over %d",
			maxRecord+1, maxRecord)
	}
}

func TestAKeepaliveRecordTakesNoPlaceInTheSequence(t *testing.T) {
	var body []byte
	body = append(body, stripeKeepalive...)
	rec := make([]byte, recHdr+2)
	binary.BigEndian.PutUint64(rec[0:8], 0)
	binary.BigEndian.PutUint32(rec[8:12], 2)
	copy(rec[recHdr:], "hi")
	body = append(body, rec...)
	body = append(body, stripeKeepalive...)

	pr, pw := io.Pipe()
	q := newReseq(pw, maxStripePend(1))
	go readStripe(io.NopCloser(bytes.NewReader(body)), q, func() { pw.Close() })

	got := make([]byte, 2)
	if _, err := io.ReadFull(pr, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("got %q, want \"hi\": a keepalive was taken for data or consumed seq 0", got)
	}
}

func TestSetHTTPDownstream(t *testing.T) {
	old := carrierStreams
	defer func() { carrierStreams = old }()

	SetHTTPStreams(0)
	if carrierStreams != old {
		t.Fatalf("zero must leave the default alone, got %d", carrierStreams)
	}
	SetHTTPStreams(4)
	if carrierStreams != 4 {
		t.Fatalf("workers not applied: %d", carrierStreams)
	}
	SetHTTPStreams(999)
	if carrierStreams != 16 {
		t.Fatalf("workers not clamped: %d", carrierStreams)
	}
}

func TestStreamsAreReleasedWhenTheirClientGoesAwayRatherThanAtTheIdleTimeout(t *testing.T) {
	h := newDownHarness(t)
	_, done := dialDown(t, h, 4)
	h.session(t, 3*time.Second)

	h.waitStreams(t, 4)

	done()
	deadline := time.Now().Add(10 * time.Second)
	for h.inFlgt.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.inFlgt.Load(); n != 0 {
		t.Fatalf("%d stream(s) still held %v after the client left; they would sit until the %v idle "+
			"reaper, and every re-dial adds a fresh set", n, 10*time.Second, connIdle)
	}
}

func TestAStreamThatCannotOpenLeavesTheCarrierRunning(t *testing.T) {
	h := newDownHarness(t)
	h.refuse.Store(1 << 30) // every extra stream is turned away, for the whole test
	conn, done := dialDown(t, h, 4)
	defer done()
	s := h.session(t, 3*time.Second)

	// Wait until all three extra streams have actually been turned away. Without that the write below
	// can finish before the refusals land, and the test passes whatever the carrier does with them.
	deadline := time.Now().Add(10 * time.Second)
	for h.tries.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := h.tries.Load(); n < 3 {
		t.Fatalf("only %d of 3 extra streams were attempted", n)
	}

	msg := []byte("one stream is a whole carrier even when the others never open")
	if _, err := s.down.write(msg, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the carrier died because an EXTRA stream could not open; only the first is required: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestAStreamThatWasTurnedAwayComesBack(t *testing.T) {
	h := newDownHarness(t)
	h.refuse.Store(3) // the first three attempts are turned away; the retry has to outlast them
	conn, done := dialDown(t, h, 2)
	defer done()
	s := h.session(t, 3*time.Second)

	deadline := time.Now().Add(20 * time.Second)
	for h.carried() < 2 && time.Now().Before(deadline) {
		if _, err := s.down.write([]byte("keep the streams fed"), 0); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 20)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if n := h.carried(); n < 2 {
		t.Fatalf("%d stream(s) carrying after %d open attempts: a stream turned away at dial never "+
			"comes back, so one bad moment costs it for the life of the carrier", n, h.tries.Load())
	}
}

func TestWhatADeadStreamWasCarryingStillArrives(t *testing.T) {
	h := newDownHarness(t)
	h.cutIdx = "1"
	h.cut.Store(0) // stream 1 refuses the first run it is handed, every time it comes back
	conn, done := dialDown(t, h, 3)
	defer done()
	s := h.session(t, 3*time.Second)

	const chunks, chunkLen = 3000, 1400
	want := make([]byte, 0, chunks*chunkLen)
	for i := 0; i < chunks; i++ {
		c := make([]byte, chunkLen)
		for j := range c {
			c[j] = byte(i*11 + j)
		}
		want = append(want, c...)
	}
	go func() {
		for i := 0; i < chunks; i++ {
			c := want[i*chunkLen : (i+1)*chunkLen]
			if _, err := s.down.write(c, 0); err != nil {
				return
			}
		}
	}()

	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the download stopped when one stream died: whatever it was carrying was never put "+
			"back, so the receiver waits on numbers that will never come: %v", err)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte %d of %d differs: a re-sent run was not put back in its place", i, len(want))
			}
		}
	}
	if n := h.cutHit.Load(); n == 0 {
		t.Fatal("the cut stream never refused a write, so this run says nothing about what happens to " +
			"a run that dies in a stream's hands")
	}
}
