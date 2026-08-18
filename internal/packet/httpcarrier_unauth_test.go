package packet

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

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

func pendBytes(s *httpcSession) (held int, entries int) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	for _, d := range s.pend {
		held += len(d)
	}
	return held, len(s.pend)
}

func TestHTTPCPostNeverCreatesSession(t *testing.T) {
	b := &TCP{httpcSessions: map[string]*httpcSession{}}
	ts := httptest.NewServer(http.HandlerFunc(b.httpcHandler))
	defer ts.Close()

	const sid = "00112233445566778899aabbccddeeff"
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

func TestHTTPCPendBufferIsBoundedInBytes(t *testing.T) {
	b := &TCP{httpcSessions: map[string]*httpcSession{}}
	const sid = "ffeeddccbbaa99887766554433221100"
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	b.httpcSessions[sid] = s
	defer pw.Close()

	ts := httptest.NewServer(http.HandlerFunc(b.httpcHandler))
	defer ts.Close()

	const chunk = 512 << 10
	for seq := 1; seq <= 32; seq++ {
		httpcPostChunk(t, ts.URL, sid, seq, chunk)
	}
	held, entries := pendBytes(s)
	if limit := maxPendBytes(); held > limit {
		t.Fatalf("session holds %d bytes in %d entries for a peer that never handshook; cap is %d",
			held, entries, limit)
	}

	if held > 8<<20 {
		t.Fatalf("session holds %d bytes (%d entries) — an unauthenticated peer must not park this much",
			held, entries)
	}
}

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
	for i := 0; i < 32; i++ {
		httpcPostChunk(t, ts.URL, sid, 1, chunk)
	}
	if held, entries := pendBytes(s); held != chunk || entries != 1 {
		t.Fatalf("after 32 re-posts of one seq the session holds %d bytes in %d entries, want %d in 1",
			held, entries, chunk)
	}

	httpcPostChunk(t, ts.URL, sid, 2, chunk)
	if _, entries := pendBytes(s); entries != 2 {
		t.Fatalf("a fresh seq was refused after duplicates: %d entries, want 2", entries)
	}
}
