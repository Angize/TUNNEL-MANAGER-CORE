package packet

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// A chunk the server THREW AWAY must not be answered 204. 204 means "chunk accepted, session stays
// open" and the client's POST worker treats it as success, so answering it for a chunk nobody has stalls
// the upstream at nextSeq forever while the downstream GET keeps streaming and the dot stays green.
// Driven through the REAL handler, with the session created the only way one can be — the downstream GET.
func TestOverflowedUpstreamChunkIsNotAnswered204(t *testing.T) {
	w0, b0, c0, i0, g0 := upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap
	defer func() { upWorkers, maxUpBatch, upChanCap, upIdleConns, upMinGap = w0, b0, c0, i0, g0 }()
	SetHTTPUpstream(1, 8, 0) // pins maxPendBytes() at its 4 MiB floor, so 1 MiB chunks trip it in five

	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "xhdrop")
	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.httpcHandler)
	ts := httptest.NewServer(mux)
	const sid = "0123456789abcdef0123456789abcdef"
	t.Cleanup(func() {
		// End the session first: the downstream GET handler parks on <-s.done, so closing the test
		// server before it returns just makes httptest wait out its own five-second grace period.
		if s := srv.httpcLookup(sid); s != nil {
			s.close(srv, sid)
		}
		ts.Close()
		srv.Close()
	})

	// The downstream GET opens the session and holds; it is the only path allowed to create one.
	go func() {
		resp, gerr := ts.Client().Get(ts.URL + "/?s=" + sid)
		if gerr == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for srv.httpcLookup(sid) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.httpcLookup(sid) == nil {
		t.Fatal("the downstream GET never created a session")
	}

	post := func(seq int, n int) int {
		req, rerr := http.NewRequest(http.MethodPost,
			ts.URL+"/?s="+sid+"&seq="+strconv.Itoa(seq), bytes.NewReader(make([]byte, n)))
		if rerr != nil {
			t.Fatalf("NewRequest: %v", rerr)
		}
		resp, perr := ts.Client().Do(req)
		if perr != nil {
			t.Fatalf("POST seq=%d: %v", seq, perr)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	// seq 0 is deliberately never sent: the gap never fills, so every chunk below just accumulates in
	// pend and nothing is ever written to the upstream pipe.
	if code := post(1, 1<<20); code != http.StatusNoContent {
		t.Fatalf("the FIRST buffered chunk got HTTP %d, want 204 — this test would pass for the wrong reason", code)
	}
	dropped := 0
	for seq := 2; seq <= 10; seq++ {
		code := post(seq, 1<<20)
		if code == http.StatusNoContent {
			continue
		}
		dropped++
		if code/100 == 2 {
			t.Fatalf("a dropped chunk got HTTP %d — any 2xx tells the client's POST worker the bytes were accepted", code)
		}
	}
	if dropped == 0 {
		t.Fatal("the pending buffer never overflowed at 10 MiB against a 4 MiB cap: a chunk the server threw away was answered 204 every time, so the client never learns the stream has a hole it will never fill")
	}
}

// ...and the retransmit case must NOT be caught by the above. A re-POST of a seq already consumed is a
// legitimate duplicate whose bytes really are in the stream; answering it with an error would make a
// healthy client tear the session down over a retransmit. This one asserts deliver's contract directly,
// because reaching the duplicate branch through the handler needs the gap to fill first.
func TestDeliverReportsSuccessForADuplicateItAlreadyDelivered(t *testing.T) {
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	drained := make(chan struct{})
	go func() { io.Copy(io.Discard, pr); close(drained) }()
	defer func() { pw.Close(); <-drained }()

	if !s.deliver(0, []byte("hello")) {
		t.Fatal("the first in-order chunk was reported as dropped")
	}
	if !s.deliver(0, []byte("hello")) {
		t.Fatal("a retransmit of an already-delivered seq is reported as dropped: the client would be told 400 and re-dial a perfectly healthy session")
	}
}
