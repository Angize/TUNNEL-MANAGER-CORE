package packet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func httpcStressServer(t *testing.T) (string, *http.Client, *TCP) {
	t.Helper()
	const psk = "server-stress-psk-abcdefghijklmnop"
	srvDev, _ := tunPair(t, "srvstress")
	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.httpcHandler)
	ts := httptest.NewServer(mux)
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL, ts.Client(), srv
}

func liveSessions(b *TCP) int {
	b.httpcMu.Lock()
	defer b.httpcMu.Unlock()
	return len(b.httpcSessions)
}

func TestHTTPCServerMalformedBlast(t *testing.T) {
	base, hc, _ := httpcStressServer(t)
	hc.Timeout = 3 * time.Second

	kinds := []func(i int) *http.Request{
		func(i int) *http.Request {
			r, _ := http.NewRequest("GET", fmt.Sprintf("%s/?s=deadbeef", base), nil)
			return r
		},
		func(i int) *http.Request {
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032d&seq=0", base, 0)+"ZZZ", nil)
			return r
		},
		func(i int) *http.Request {
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x&seq=notanumber", base, i), bytes.NewReader([]byte("x")))
			return r
		},
		func(i int) *http.Request {
			r, _ := http.NewRequest("PUT", fmt.Sprintf("%s/?s=%032x", base, i), nil)
			return r
		},
		func(i int) *http.Request {
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x", base, i), bytes.NewReader(bytes.Repeat([]byte{0xff}, 300)))
			r.Header.Set("Content-Type", "application/grpc")
			return r
		},
		func(i int) *http.Request {
			r, _ := http.NewRequest("POST", fmt.Sprintf("%s/?s=%032x&seq=%d", base, i, i), bytes.NewReader(bytes.Repeat([]byte{0x41}, 200000)))
			return r
		},
	}

	var wg sync.WaitGroup
	for w := 0; w < 40; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				req := kinds[(w+i)%len(kinds)](w*1000 + i)
				resp, err := hc.Do(req)
				if err != nil {
					continue
				}
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
				resp.Body.Close()
			}
		}(w)
	}
	wg.Wait()

	resp, err := hc.Get(base + "/?s=short")
	if err != nil {
		t.Fatalf("server unresponsive after malformed blast: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a bad sid after the blast, got %d", resp.StatusCode)
	}
}

func TestHTTPCServerSessionChurn(t *testing.T) {
	base, hc, srv := httpcStressServer(t)
	hc.Timeout = 2 * time.Second

	var wg sync.WaitGroup
	for w := 0; w < 30; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				sid := fmt.Sprintf("%032x", w*100000+i)
				ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)

				var gwg sync.WaitGroup
				gwg.Add(1)
				go func() {
					defer gwg.Done()
					gr, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/?s=%s", base, sid), nil)
					if resp, err := hc.Do(gr); err == nil {
						io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
						resp.Body.Close()
					}
				}()
				time.Sleep(2 * time.Millisecond)
				pr, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/?s=%s&seq=0", base, sid), bytes.NewReader([]byte("hi")))
				if resp, err := hc.Do(pr); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				cancel()
				gwg.Wait()
			}
		}(w)
	}
	wg.Wait()

	resp, err := hc.Get(base + "/?s=short")
	if err != nil {
		t.Fatalf("server unresponsive after session churn: %v", err)
	}
	resp.Body.Close()
	if n := liveSessions(srv); n > 600 {
		t.Fatalf("HTTP-carrier session table unbounded after churn: %d live sessions", n)
	}
	t.Logf("session-churn soak: server alive after 600 churned sessions, table=%d", liveSessions(srv))
}
