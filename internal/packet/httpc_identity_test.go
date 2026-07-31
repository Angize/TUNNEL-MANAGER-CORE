package packet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPostLadderSendsChromesAcceptEncoding is the regression test for the POST ladder contradicting
// its own fingerprint.
//
// In user terms: the operator picks the http carrier shape because a CDN streams POSTs instead of
// buffering them. The request that reaches the CDN claims to be Chrome 133 twice over — the
// User-Agent and the uTLS JA3 — and then offered `Accept-Encoding: gzip`, which Go's transport adds
// when the header is unset. No browser has sent gzip alone in a decade, and comparing the advertised
// browser against the headers it sends is exactly what a CDN's bot management does. The ws shape
// hand-builds Chrome's full block for this reason; the POST ladder sent four headers and no sec-*
// header at all.
func TestPostLadderSendsChromesAcceptEncoding(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req, err := http.NewRequest("POST", srv.URL+"/x", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	browserHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// What the SERVER saw, not what we set — Go's transport is what added the old value.
	if ae := got.Get("Accept-Encoding"); ae != chromeAcceptEncoding {
		t.Fatalf("the edge saw Accept-Encoding %q; want Chrome's %q. Go adds its own \"gzip\" whenever the "+
			"header is unset, which contradicts the Chrome UA and JA3 on the same request", ae, chromeAcceptEncoding)
	}
	if got.Get("User-Agent") != chromeUA {
		t.Fatalf("User-Agent = %q, want %q", got.Get("User-Agent"), chromeUA)
	}
	for _, h := range chromeClientHints {
		if v := got.Get(h[0]); v != h[1] {
			t.Fatalf("the edge saw %s = %q, want %q — no Chrome since 89 omits the sec-* block", h[0], v, h[1])
		}
	}
	if o := got.Get("Origin"); !strings.HasPrefix(o, "https://") {
		t.Fatalf("Origin = %q; Chrome does send Origin on a same-origin POST", o)
	}
}

// TestDownstreamGetSendsNoOrigin is the other half, and it is the one that was wrong.
//
// Chrome appends Origin for a CORS request and, otherwise, only for methods other than GET and HEAD.
// So it sends Origin on the POST above and NEVER on a same-origin GET. Setting it on both put a
// header combination on the wire that no Chrome produces — on the single most distinctive request
// this carrier makes: one long-lived downstream GET per session, carrying it right beside the
// Sec-Fetch-Site: same-origin that is supposed to make the request look ordinary. A CDN bot-
// management rule that cross-checks Fetch Metadata against Origin sees the anomaly on exactly the
// request the header block exists to protect.
func TestDownstreamGetSendsNoOrigin(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	browserHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if o := got.Get("Origin"); o != "" {
		t.Fatalf("the edge saw Origin=%q on a same-origin GET — no Chrome sends that, and this is the "+
			"one request per session that stays open", o)
	}
	// The rest of the identity must still be there: this is not a licence to drop the block.
	if got.Get("User-Agent") != chromeUA {
		t.Fatalf("User-Agent = %q, want %q", got.Get("User-Agent"), chromeUA)
	}
	if ae := got.Get("Accept-Encoding"); ae != chromeAcceptEncoding {
		t.Fatalf("Accept-Encoding = %q, want %q", ae, chromeAcceptEncoding)
	}
	for _, h := range chromeClientHints {
		if v := got.Get(h[0]); v != h[1] {
			t.Fatalf("the edge saw %s = %q, want %q", h[0], v, h[1])
		}
	}
}

// TestClientHintsMatchTheUA keeps the two halves of one identity in step. A sec-ch-ua brand list
// naming a different Chrome major than the User-Agent — or a platform that disagrees with it — is a
// fresh contradiction in place of the one being fixed, and it is the same class of drift
// TestUserAgentMatchesTLSParrot exists to catch on the TLS side.
func TestClientHintsMatchTheUA(t *testing.T) {
	major := chromeUA[strings.Index(chromeUA, "Chrome/")+len("Chrome/"):]
	major = major[:strings.Index(major, ".")]

	hints := map[string]string{}
	for _, h := range chromeClientHints {
		hints[h[0]] = h[1]
	}
	if !strings.Contains(hints["sec-ch-ua"], `"Google Chrome";v="`+major+`"`) {
		t.Fatalf("sec-ch-ua %q does not name Chrome %s, which is what the User-Agent claims",
			hints["sec-ch-ua"], major)
	}
	if !strings.Contains(hints["sec-ch-ua"], `"Chromium";v="`+major+`"`) {
		t.Fatalf("sec-ch-ua %q must name the same Chromium major, %s", hints["sec-ch-ua"], major)
	}
	// chromeUA says Windows NT 10.0; the platform hint has to agree.
	if strings.Contains(chromeUA, "Windows NT") != (hints["sec-ch-ua-platform"] == `"Windows"`) {
		t.Fatalf("sec-ch-ua-platform %q disagrees with the platform in the User-Agent %q",
			hints["sec-ch-ua-platform"], chromeUA)
	}
	if strings.Contains(chromeUA, "Mobile") != (hints["sec-ch-ua-mobile"] == "?1") {
		t.Fatalf("sec-ch-ua-mobile %q disagrees with the User-Agent", hints["sec-ch-ua-mobile"])
	}
}

// TestGrpcModeStillSendsNoBrowserHeaders pins that the block above did not leak into grpc mode. A
// gRPC call is not something a browser can make, so Chrome client hints on an application/grpc
// request would be the same lie told the other way round — the contradiction core #205 removed.
func TestGrpcModeStillSendsNoBrowserHeaders(t *testing.T) {
	req, err := http.NewRequest("POST", "https://edge.example/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	grpcHeaders(req)
	if ua := req.Header.Get("User-Agent"); ua == chromeUA {
		t.Fatalf("grpc mode is wearing the browser User-Agent again: %q", ua)
	}
	for _, h := range chromeClientHints {
		if v := req.Header.Get(h[0]); v != "" {
			t.Fatalf("grpc mode sent the browser hint %s = %q; no gRPC client sends it and no browser "+
				"can make a gRPC call", h[0], v)
		}
	}
	if ae := req.Header.Get("Accept-Encoding"); ae != "" {
		t.Fatalf("grpc mode set Accept-Encoding %q; grpc-go sends none and the transport disables it", ae)
	}
}

// TestIdentityEncodingIsNotAFailure pins the downstream Content-Encoding guard from both sides.
//
// The guard is real and necessary: setting Accept-Encoding by hand turns off Go's transparent
// decompression, and the downstream body IS the data plane, so a genuinely compressed response must
// fail the dial rather than feed compressed bytes into the AEAD. But it first refused ANY non-empty
// value, including "identity" — the spec's own name for "not encoded" — which turned a legal,
// perfectly decodable response into a tunnel that would not come up.
func TestIdentityEncodingIsNotAFailure(t *testing.T) {
	for _, ok := range []string{"", "identity", "IDENTITY", " identity ", "Identity"} {
		if downstreamUnusable(ok) {
			t.Fatalf("Content-Encoding %q means the body is NOT encoded — refusing it refuses a working "+
				"edge; case and space in a header token must not decide whether a tunnel starts", ok)
		}
	}
	for _, bad := range []string{"gzip", "br", "zstd", "GZIP", " deflate"} {
		if !downstreamUnusable(bad) {
			t.Fatalf("Content-Encoding %q would reach the framer as compressed bytes and the tunnel would "+
				"carry garbage behind a green dot — it has to fail the dial", bad)
		}
	}
}
