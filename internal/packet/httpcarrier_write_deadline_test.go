package packet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// The httpc carrier had a write deadline that was recorded and never enforced: connFramer arms
// now+writeTimeout immediately before every framed write, and the only check was a comparison at the
// TOP of Write — so it always passed, and the write underneath then parked with no bound at all.
// These tests drive each of the four writers that can park, and assert the write RETURNS.
//
// Why it matters, in order of damage: on the client the POST ladder parks under cf.mu, which is the
// same lock writeFrame holds, so the TUN reader and the keepalive loop park with it — and while
// anything is still arriving downstream, lastRx keeps the panel dot green over a tunnel whose
// upstream is completely dead. On the server the parked write holds the goroutine that drains the TUN.

// tarpitServer answers nothing: it drains the request body and then holds the handler, which is what a
// CDN edge under load does to an origin. Returns the server and the func that releases it.
func tarpitServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	block := make(chan struct{})
	var once atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-block
	}))
	release := func() {
		if once.CompareAndSwap(false, true) {
			close(block)
		}
	}
	t.Cleanup(func() { release(); srv.Close() })
	return srv, release
}

// A jammed POST ladder must fail the write, not swallow it. Every queue in front of the workers is
// finite (upWorkers in flight, upWorkCap batches waiting, upChanCap chunks queued), so once a
// tarpitting edge holds every worker the enqueue blocks — and it is reached from writeFrame under
// cf.mu, so it takes tunLoop and the keepalive loop down with it. Nothing recovers that until the
// read side happens to time out, which a tunnel that is still receiving never does.
func TestHTTPCUpstreamEnqueueHonoursTheWriteDeadline(t *testing.T) {
	w0, b0, c0, i0, g0 := upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap
	defer func() { upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap = w0, b0, c0, i0, g0 }()
	SetHTTPUpstream(1, 8, 0) // one worker, 8 KiB batches: the ladder jams after a handful of chunks

	srv, _ := tarpitServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := newHTTPCUp(ctx, srv.Client(),
		func(seq uint64) string { return srv.URL + "/?s=x&seq=" + strconv.FormatUint(seq, 10) },
		func(*http.Request) {}, func() {})

	chunk := make([]byte, 1400)
	var last error
	for i := 0; i < 200 && last == nil; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := u.write(chunk, time.Now().Add(400*time.Millisecond).UnixNano())
			done <- err
		}()
		select {
		case last = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("write #%d parked past its deadline — writeFrame holds cf.mu, so the TUN reader and the keepalive loop are parked with it", i)
		}
	}
	if !errors.Is(last, os.ErrDeadlineExceeded) {
		t.Fatalf("a jammed ladder returned %v; want os.ErrDeadlineExceeded so the framer fails the conn and re-dials", last)
	}
}

// One POST must be bounded end to end. The request rode the SESSION context, which is cancelled only
// when the conn closes — so an edge that completes TCP+TLS, takes the body and never answers held a
// worker for the life of the session, and upWorkers of those are the whole ladder.
func TestHTTPCUpstreamPostCannotHoldAWorkerForever(t *testing.T) {
	p0 := upPostTimeout
	defer func() { upPostTimeout = p0 }()
	upPostTimeout = 300 * time.Millisecond

	srv, _ := tarpitServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failed atomic.Bool
	u := newHTTPCUp(ctx, srv.Client(),
		func(seq uint64) string { return srv.URL + "/?s=x&seq=" + strconv.FormatUint(seq, 10) },
		func(*http.Request) {}, func() { failed.Store(true) })

	if _, err := u.write(make([]byte, 100), 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for !failed.Load() {
		select {
		case <-deadline:
			t.Fatal("a tarpitted POST never returned: the worker is held for the life of the session, and upWorkers of these are the whole upstream")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// SERVER, both shapes. c.w is the ResponseWriter of a long-lived response; when the peer stops
// reading, the socket (HTTP/1) or the stream window (h2) fills and the write parks forever, holding
// the goroutine that drains the TUN. Driven through newHTTPCServerConn — the one constructor both
// real handlers use — against a real ResponseWriter and a real client that reads the headers and then
// never reads the body.
func TestHTTPCServerWriteFailsInsteadOfParkingWhenThePeerStopsReading(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"h2c", true}} {
		t.Run(tc.name, func(t *testing.T) {
			out := make(chan error, 1)
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fl, ok := w.(http.Flusher)
				if !ok {
					out <- errors.New("ResponseWriter is not a Flusher")
					return
				}
				w.WriteHeader(http.StatusOK)
				fl.Flush()
				conn := newHTTPCServerConn(w, nil, w, fl.Flush, r.RemoteAddr, nil)
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				buf := make([]byte, 64<<10)
				var err error
				t0 := time.Now()
				for err == nil && time.Since(t0) < 6*time.Second {
					_, err = conn.Write(buf)
				}
				out <- err
			})

			ts := httptest.NewUnstartedServer(h)
			if tc.h2 {
				ts.EnableHTTP2 = true
				ts.StartTLS() // HTTP/2 — the same responseWriter the h2c origin listener serves
			} else {
				ts.Start()
			}
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			// Deliberately never read resp.Body: this IS the stalled peer.
			defer resp.Body.Close()

			select {
			case err := <-out:
				if err == nil {
					t.Fatal("the server absorbed every byte it wrote to a peer that stopped reading — nothing bounded the write")
				}
				t.Logf("server write failed as it should: %v", err)
			case <-time.After(15 * time.Second):
				t.Fatal("the server write parked past its deadline — the goroutine draining the TUN is held forever")
			}
		})
	}
}

// CLIENT, grpc shape. Here the writer is an io.Pipe feeding the request body, and the pipe's reader is
// Go's h2 transport: once the server stops reading, the stream window fills, the transport stops
// draining the pipe, and Write parks. A pipe offers no deadline handle, so the deadline has to close
// the conn — which is what a write error causes here anyway. The whole client path is real
// (establishHTTPC -> dialHTTPCGrpc); only the far end is a stub that never reads the body.
func TestHTTPCClientGrpcWriteFailsInsteadOfParkingOnAStalledPeer(t *testing.T) {
	stall := make(chan struct{})
	defer close(stall)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush() // let the client's establish return, then never read r.Body
		}
		<-stall
	})
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	b := &TCP{addr: ts.Listener.Addr().String(), ws: true, httpc: true, httpcMode: "grpc",
		wsPath: "/", wsTLS: true, httpcTLS: &tls.Config{InsecureSkipVerify: true}}
	conn, _, _, err := b.establishHTTPC(true)
	if err != nil {
		t.Fatalf("establishHTTPC: %v", err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	out := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		var werr error
		t0 := time.Now()
		for werr == nil && time.Since(t0) < 6*time.Second {
			_, werr = conn.Write(buf)
		}
		out <- werr
	}()

	select {
	case werr := <-out:
		if werr == nil {
			t.Fatal("the client absorbed every byte it wrote to a peer that never reads the request body — nothing bounded the write")
		}
		t.Logf("client grpc write failed as it should: %v", werr)
	case <-time.After(15 * time.Second):
		t.Fatal("the client grpc write parked past its deadline — it holds cf.mu, so the TUN reader and the keepalive loop are parked with it")
	}
}
