package packet

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// nonFlusherWriter is an http.ResponseWriter that deliberately does NOT implement http.Flusher, which
// is the one thing the GET handler bails out on after it has done its argument checks. net/http's own
// writer always implements Flusher, so this is the only way to drive that branch at all — and driving
// it is the point: it was the single statement that could return between "create the session" and
// "start serving it", i.e. the only way to produce the orphan the reap watchdog existed for.
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

// TestHTTPCGetNeverLeavesAnUnservedSession replaces the reap watchdog with the property that made it
// dead: no request can leave a session created and never served.
//
// The watchdog armed a 10 s timer per session and its reap branch had become unreachable — after #200
// the downstream GET is the only creator and close(s.served) happened a few statements later in the
// same handler. Its test built both sessions by hand in the map and called reapIfUnserved directly,
// so it was green either way and said nothing about reachability. The one real gap was the Flusher
// assertion sitting BETWEEN the create and the serve; that check now runs first, so the branch is not
// merely unreachable today, it cannot be produced.
//
// Both halves are needed: the bail-out must allocate nothing, and the ordinary GET must still create
// AND serve — otherwise "no sessions, ever" would pass.
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
		// httptest's recorder DOES implement Flusher, so this takes the real path.
		go func() {
			defer close(done)
			b.httpcHandler(rec, httptest.NewRequest(http.MethodGet, "/?s="+sid, nil))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the GET handler never returned")
		}

		// The session itself is NOT observable through the map here and that is correct: on a bare
		// TCP the serve goroutine dies at once and its closeFn deletes the entry, so polling the map
		// is a race by construction. What IS deterministic is that these are written only AFTER
		// httpcGetOrCreate returns — the response head is the create's own downstream evidence.
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
