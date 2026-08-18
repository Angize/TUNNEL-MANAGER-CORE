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

func TestHTTPCUpstreamEnqueueHonoursTheWriteDeadline(t *testing.T) {
	w0, b0, c0, i0, g0 := upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap
	defer func() { upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap = w0, b0, c0, i0, g0 }()
	SetHTTPUpstream(1, 8, 0)

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
				ts.StartTLS()
			} else {
				ts.Start()
			}
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}

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

func TestHTTPCServerWriteDeadlineCoversTheFlushAtFrameSize(t *testing.T) {
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

				buf := make([]byte, 1452)
				var err error
				t0 := time.Now()
				for err == nil && time.Since(t0) < 30*time.Second {
					_, err = conn.Write(buf)
				}
				out <- err
			})

			ts := httptest.NewUnstartedServer(h)
			if tc.h2 {
				ts.EnableHTTP2 = true
				ts.StartTLS()
			} else {
				ts.Start()
			}
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			select {
			case err := <-out:
				if err == nil {
					t.Fatal("the server absorbed every byte at frame size — nothing bounded the write")
				}
				t.Logf("server write failed as it should: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("a frame-sized server write parked past its deadline: the deadline is disarmed before the flush, which is where all the socket I/O happens")
			}
		})
	}
}

func TestHTTPCClientGrpcWriteFailsInsteadOfParkingOnAStalledPeer(t *testing.T) {
	stall := make(chan struct{})
	defer close(stall)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-stall
	})
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	b := &TCP{addr: ts.Listener.Addr().String(), ws: true, httpc: true, httpcMode: "grpc",
		wsPath: "/", wsTLS: true, httpcTLS: &tls.Config{InsecureSkipVerify: true}}
	conn, _, _, err := b.establishHTTPC()
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
