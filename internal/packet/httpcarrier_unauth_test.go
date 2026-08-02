package packet

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// httpcPostChunk posts one upstream chunk through the REAL handler and returns the status code.
func httpcPostChunk(t *testing.T, base, sid string, seq int, n int) int {
	t.Helper()
	url := base + "?s=" + sid + "&seq=" + strconv.Itoa(seq)
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(make([]byte, n)))
	if err != nil {
		t.Fatalf("POST seq=%d: %v", seq, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// pendBytes sums the bytes the session is holding for chunks that have not been delivered yet.
// Read off the map itself (not the running total) so the assertion says nothing about HOW the
// bound is implemented — only that the peer cannot make the server hold this much.
func pendBytes(s *httpcSession) (held int, entries int) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	for _, d := range s.pend {
		held += len(d)
	}
	return held, len(s.pend)
}

// TestHTTPCPostNeverCreatesSession locks in the rule that the upstream POST path may not ALLOCATE. A
// session is created by the downstream GET and only by it, so a POST for an id the server never served
// is always a scanner or a stale straggler. Letting it create one — a pipe, a timer and a whole
// out-of-order buffer, with no handshake and no cap — lets anyone reaching the origin OOM the node.
func TestHTTPCPostNeverCreatesSession(t *testing.T) {
	b := &TCP{httpcSessions: map[string]*httpcSession{}}
	ts := httptest.NewServer(http.HandlerFunc(b.httpcHandler))
	defer ts.Close()

	const sid = "00112233445566778899aabbccddeeff" // well-formed, never served
	if code := httpcPostChunk(t, ts.URL, sid, 0, 4096); code != http.StatusNotFound {
		t.Fatalf("POST for an unknown session answered %d, want 404", code)
	}
	b.httpcMu.Lock()
	n := len(b.httpcSessions)
	b.httpcMu.Unlock()
	if n != 0 {
		t.Fatalf("a POST for an unknown session created %d session(s); only the GET may create", n)
	}
}

// TestHTTPCPendBufferIsBoundedInBytes drives real POSTs through the handler with a permanent gap at
// seq 0, so nothing can ever drain and every chunk stays buffered. The old guard bounded the ENTRY
// COUNT (1024) and not the bytes, and a chunk is up to maxPostBody (1 MiB), so one session could
// park ~1 GiB. This is the assertion that goes red on the pre-fix code.
func TestHTTPCPendBufferIsBoundedInBytes(t *testing.T) {
	b := &TCP{httpcSessions: map[string]*httpcSession{}}
	const sid = "ffeeddccbbaa99887766554433221100"
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	b.httpcSessions[sid] = s
	defer pw.Close()

	ts := httptest.NewServer(http.HandlerFunc(b.httpcHandler))
	defer ts.Close()

	// seq 0 is never sent, so nextSeq stays 0 and NOTHING is ever handed to the pipe.
	const chunk = 512 << 10
	for seq := 1; seq <= 32; seq++ { // 16 MiB offered
		httpcPostChunk(t, ts.URL, sid, seq, chunk)
	}
	held, entries := pendBytes(s)
	if limit := maxPendBytes(); held > limit {
		t.Fatalf("session holds %d bytes in %d entries for a peer that never handshook; cap is %d",
			held, entries, limit)
	}
	// A generous absolute ceiling too, so the test still means something if the cap formula changes.
	if held > 8<<20 {
		t.Fatalf("session holds %d bytes (%d entries) — an unauthenticated peer must not park this much",
			held, entries)
	}
}

// TestHTTPCPendAccountingSurvivesRepostedSeq guards the accounting itself: re-posting a seq that is
// still waiting REPLACES its chunk, so it must not be counted twice. Getting that wrong makes the
// byte bound tighten on every duplicate until a legitimate client's chunks are silently refused —
// a stall that looks exactly like packet loss. Drives the real handler, not deliver().
func TestHTTPCPendAccountingSurvivesRepostedSeq(t *testing.T) {
	b := &TCP{httpcSessions: map[string]*httpcSession{}}
	const sid = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	b.httpcSessions[sid] = s
	defer pw.Close()

	ts := httptest.NewServer(http.HandlerFunc(b.httpcHandler))
	defer ts.Close()

	const chunk = 512 << 10
	for i := 0; i < 32; i++ { // the SAME waiting seq, over and over
		httpcPostChunk(t, ts.URL, sid, 1, chunk)
	}
	if held, entries := pendBytes(s); held != chunk || entries != 1 {
		t.Fatalf("after 32 re-posts of one seq the session holds %d bytes in %d entries, want %d in 1",
			held, entries, chunk)
	}
	// ...and a NEW seq is still accepted, i.e. the bound was not eaten by the duplicates.
	httpcPostChunk(t, ts.URL, sid, 2, chunk)
	if _, entries := pendBytes(s); entries != 2 {
		t.Fatalf("a fresh seq was refused after duplicates: %d entries, want 2", entries)
	}
}
