package packet

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type nonFlusherWriter struct {
	hdr    http.Header
	status int
}

func (n *nonFlusherWriter) Header() http.Header {
	if n.hdr == nil {
		n.hdr = http.Header{}
	}
	return n.hdr
}
func (n *nonFlusherWriter) Write(p []byte) (int, error) { return len(p), nil }
func (n *nonFlusherWriter) WriteHeader(code int)        { n.status = code }

func TestHTTPCGetNeverLeavesAnUnservedSession(t *testing.T) {
	const sid = "00112233445566778899aabbccddeeff"

	t.Run("a writer we cannot flush allocates nothing", func(t *testing.T) {
		b := &TCP{httpcSessions: map[string]*httpcSession{}}
		w := &nonFlusherWriter{}
		b.httpcHandler(w, httptest.NewRequest(http.MethodGet, "/?s="+sid, nil))

		if w.status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 — this test did not reach the branch it is about", w.status)
		}
		if n := len(b.httpcSessions); n != 0 {
			t.Fatalf("%d session(s) left behind by a request that was answered 500. Nothing will ever "+
				"serve them and nothing reaps them now, so each one holds an io.Pipe until the process "+
				"exits — and any caller that can reach the origin could ask for one per id", n)
		}
	})

	t.Run("an ordinary GET still gets past the check and serves", func(t *testing.T) {
		b := &TCP{httpcSessions: map[string]*httpcSession{}}
		rec := httptest.NewRecorder()
		done := make(chan struct{})

		go func() {
			defer close(done)
			b.httpcHandler(rec, httptest.NewRequest(http.MethodGet, "/?s="+sid, nil))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the GET handler never returned")
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: the ordinary path did not reach the serve, so the "+
				"assertion above could be passing for the wrong reason", rec.Code)
		}
		for k, want := range map[string]string{
			"Content-Type":      "application/octet-stream",
			"X-Accel-Buffering": "no",
		} {
			if got := rec.Header().Get(k); got != want {
				t.Fatalf("%s = %q, want %q — the handler did not get past httpcGetOrCreate", k, got, want)
			}
		}
	})
}
