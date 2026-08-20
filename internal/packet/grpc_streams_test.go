package packet

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A real grpc origin over h2: the handler, the session and the records are the production ones. The
// server's own conn parks on the upstream pipe because the test never speaks the tunnel protocol,
// which is what keeps the session open.
type grpcHarness struct {
	srv    *httptest.Server
	b      *TCP
	inFlgt atomic.Int64
	cutIdx string
	cut    atomic.Int64
	cutHit atomic.Int64
	mu     sync.Mutex
	used   []*bool
}

func (h *grpcHarness) carried() int {
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

func newGrpcHarness(t *testing.T) *grpcHarness {
	t.Helper()
	h := &grpcHarness{b: &TCP{
		ws: true, httpc: true, idle: connIdle, ping: pingEvery,
		preAuth: make(chan struct{}, maxPreAuthConns), httpcSessions: make(map[string]*httpcSession),
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		wrote := new(bool)
		h.mu.Lock()
		h.used = append(h.used, wrote)
		h.mu.Unlock()
		h.inFlgt.Add(1)
		defer h.inFlgt.Add(-1)
		var rw http.ResponseWriter = streamCounter{ResponseWriter: w, wrote: wrote}
		if h.cutIdx != "" && r.URL.Query().Get("d") == h.cutIdx {
			h.cutHit.Add(0)
			rw = cutWriter{ResponseWriter: rw, left: &h.cut, hit: &h.cutHit}
		}
		h.b.httpcHandler(rw, r)
	})
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	h.srv = ts
	t.Cleanup(ts.Close)
	return h
}

func (h *grpcHarness) session(t *testing.T, d time.Duration) *httpcSession {
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
	t.Fatal("no session was created by the grpc streams")
	return nil
}

func (h *grpcHarness) sessions() int {
	h.b.httpcMu.Lock()
	defer h.b.httpcMu.Unlock()
	return len(h.b.httpcSessions)
}

func dialGrpc(t *testing.T, h *grpcHarness, n int) (net.Conn, func()) {
	t.Helper()
	old := carrierStreams
	carrierStreams = n
	t.Cleanup(func() { carrierStreams = old })

	cl := &TCP{addr: h.srv.Listener.Addr().String(), ws: true, httpc: true, httpcMode: "grpc",
		wsPath: "/", wsTLS: true, httpcTLS: &tls.Config{InsecureSkipVerify: true}}
	conn, _, _, err := cl.establishHTTPC()
	if err != nil {
		t.Fatalf("establishHTTPC: %v", err)
	}
	return conn, func() { conn.Close() }
}

func TestAGrpcCarrierSpreadsAcrossItsStreams(t *testing.T) {
	h := newGrpcHarness(t)
	conn, done := dialGrpc(t, h, 4)
	defer done()
	s := h.session(t, 5*time.Second)

	const chunks, chunkLen = 400, 1400
	want := make([]byte, 0, chunks*chunkLen)
	for i := 0; i < chunks; i++ {
		c := make([]byte, chunkLen)
		for j := range c {
			c[j] = byte(i*13 + j)
		}
		want = append(want, c...)
	}
	go func() {
		for i := 0; i < chunks; i++ {
			if _, err := s.down.write(want[i*chunkLen:(i+1)*chunkLen], 0); err != nil {
				return
			}
		}
	}()

	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte %d of %d differs: the records were reassembled out of order", i, len(want))
			}
		}
	}
	if n := h.carried(); n < 2 {
		t.Fatalf("only %d of 4 grpc streams carried any bytes: the carrier is still one call and its "+
			"ceiling is still one flow-control window", n)
	}
}

func TestAGrpcCarrierOutlivesOneOfItsStreams(t *testing.T) {
	h := newGrpcHarness(t)
	h.cutIdx = "1"
	h.cut.Store(0) // stream 1 refuses the first run it is handed
	conn, done := dialGrpc(t, h, 3)
	defer done()
	s := h.session(t, 5*time.Second)

	const chunks, chunkLen = 2000, 1400
	want := make([]byte, 0, chunks*chunkLen)
	for i := 0; i < chunks; i++ {
		c := make([]byte, chunkLen)
		for j := range c {
			c[j] = byte(i*17 + j)
		}
		want = append(want, c...)
	}
	go func() {
		for i := 0; i < chunks; i++ {
			if _, err := s.down.write(want[i*chunkLen:(i+1)*chunkLen], 0); err != nil {
				return
			}
		}
	}()

	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the carrier died with one stream of three gone: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("what the dead stream was carrying did not come back in its place")
	}
	if h.cutHit.Load() == 0 {
		t.Fatal("the cut stream never refused a write, so this run says nothing")
	}
}

func TestAGrpcCarrierEndsWithItsLastStream(t *testing.T) {
	h := newGrpcHarness(t)
	conn, done := dialGrpc(t, h, 1)
	defer done()
	h.session(t, 5*time.Second)

	if n := h.sessions(); n != 1 {
		t.Fatalf("%d sessions, want 1", n)
	}
	conn.Close()

	// The session must go with the stream. Holding it open until the idle reaper is what left a
	// goroutine per rotation behind.
	deadline := time.Now().Add(10 * time.Second)
	for h.sessions() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := h.sessions(); n != 0 {
		t.Fatalf("%d session(s) still open %v after the only stream went; they would sit until the %v "+
			"idle reaper and every rotation would add another", n, 10*time.Second, connIdle)
	}
}
