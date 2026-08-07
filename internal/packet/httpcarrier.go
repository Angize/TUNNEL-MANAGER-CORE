// HTTP carrier: the core stream rides plain HTTP requests instead of a WebSocket upgrade, so it passes
// through CDNs that block or don't proxy WebSocket while still looking like ordinary HTTPS.
//
//	downstream (server -> client): one long-lived GET whose streaming response body carries the frames
//	upstream   (client -> server): a POST LADDER — each write is a short, discrete POST carrying one
//	                               chunk plus a monotonic seq, which a CDN forwards at once where it
//	                               would buffer a single long streaming request body
//	correlation:                   a random session id in the query ties the GET and the POSTs together
//
// Both directions present a byte stream, so httpcConn is a net.Conn and connFramer rides on top
// unchanged. The same fronting fields as ws apply; the server stays plain (the CDN terminates TLS).
package packet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	utls "github.com/refraction-networking/utls"
)

// chromeUA is the browser User-Agent presented by the ws AND HTTP carriers (single source of truth).
// Its Chrome MAJOR version MUST match the uTLS ClientHello parrot, or the JA3/JA4 computed on the TLS
// handshake and the app-layer UA advertise different Chrome versions — a combination no real browser
// produces. TestUserAgentMatchesTLSParrot fails the build if the two drift apart.
const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// chromeAcceptEncoding is the Accept-Encoding the SAME Chrome sends; it is one identity with chromeUA.
// Chrome has advertised zstd by default since 123, so a request claiming Chrome 133 while offering only
// "gzip, deflate, br" is a pre-123 browser wearing a post-123 User-Agent — exactly the cross-check a
// CDN's bot management runs. TestAcceptEncodingMatchesUAMajor keeps the two in step.
const chromeAcceptEncoding = "gzip, deflate, br, zstd"

// grpcUA is the User-Agent presented in grpc mode. A gRPC call is not something a browser can make
// (Content-Type: application/grpc and TE: trailers are forbidden to browser fetch/XHR), so the POST
// ladder's browser identity would claim Chrome while carrying headers Chrome may not send. It moves
// together with the TLS fingerprint — grpc mode presents Go's own ClientHello, as grpc-go does.
const grpcUA = "grpc-go/1.65.0"

// grpcAcceptEncoding is the message-compression list grpc-go advertises with the gzip compressor
// registered, which is the common deployment. Its ABSENCE was part of the tell.
const grpcAcceptEncoding = "gzip"

// maxPostBody caps a single upstream POST body so a hostile client can't force a huge alloc.
const maxPostBody = 1 << 20

// httpcHeaderWait bounds the wait for an establishing request's response HEADERS (the downstream GET,
// or the grpc POST) — the phase the TCP dial and TLS timeouts do NOT cover. A CDN that completes
// TCP+TLS but never streams the origin leg would otherwise block establishment forever, which is what
// freezes rotation and the manual pin. Derived from the caller's budget, so a probe honours its own.
func httpcHeaderWait(budget time.Duration) time.Duration { return 3 * budget }

// strAddr is a net.Addr for an HTTP-carrier conn (there is no single socket behind it).
type strAddr string

func (a strAddr) Network() string { return "http" }
func (a strAddr) String() string  { return string(a) }

// httpcConn presents the GET(down) + POST-ladder(up) pair (client) or the reassembled upstream
// pipe + downstream ResponseWriter (server) as a single net.Conn. On the client, Write goes to
// the POST-ladder sender (up); on the server, Write goes to the GET response writer (w). Read
// deadlines are honoured by an idle timer that closes the conn when it fires.
type httpcConn struct {
	r     io.Reader
	w     io.Writer
	flush func()
	up    *httpcUp // client only: POST-ladder upstream sender (nil on the server)

	wmu     sync.Mutex
	wdl     atomic.Int64 // unix-nanos write deadline (0 = none); ENFORCED by Write, not merely recorded
	setWD   func(time.Time) error
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	ra, la  net.Addr
}

func (c *httpcConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// armWrite makes the pending write deadline BITE for one write and returns the func that disarms it.
// Every httpc writer parks forever when the far side stalls, so the deadline has to interrupt a write
// ALREADY in flight: the server expires it through ResponseController (failing only THIS write), the
// grpc client closes the conn. A timer, because the deadline underneath OUTLIVES the write that set it.
func (c *httpcConn) armWrite() func() {
	dl := c.wdl.Load()
	if dl == 0 {
		return func() {}
	}
	t := time.AfterFunc(time.Until(time.Unix(0, dl)), func() {
		if c.setWD != nil {
			_ = c.setWD(time.Unix(0, 1)) // in the past: fails the write in flight, nothing else
			return
		}
		c.Close()
	})
	return func() { t.Stop() }
}

func (c *httpcConn) Write(p []byte) (int, error) {
	if c.up != nil { // client: each write becomes a short POST with a seq
		return c.up.write(p, c.wdl.Load())
	}
	// Two independent guards, cheapest-and-most-definitive first.
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		// net/http forbids touching a ResponseWriter once its handler has returned, and Close is what
		// releases the handler. Without this guard a late framer write — a keepalive racing teardown —
		// reached a dead ResponseWriter, which is undefined behaviour rather than a clean error.
		return 0, net.ErrClosed
	}
	if dl := c.wdl.Load(); dl != 0 && time.Now().UnixNano() > dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// The flush is INSIDE the armed window, and that is the point of arming it. Both server writers buffer
	// a frame-sized write (net/http's HTTP/1 bufio, x/net/http2's chunk buffer) and flush after every
	// frame, so c.w.Write never reaches the wire: all the socket I/O, and all the blocking, is c.flush().
	disarm := c.armWrite()
	n, err := c.w.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	disarm()
	return n, err
}

func (c *httpcConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	fn := c.closeFn
	c.mu.Unlock()
	// Closing the reader is what actually unblocks a Read parked in c.r.Read — closeFn tears the
	// session down but does not interrupt an in-flight body/pipe read. Both readers (http body,
	// io.PipeReader) implement io.Closer and return an error to the blocked reader on close.
	if rc, ok := c.r.(io.Closer); ok {
		rc.Close()
	}
	if fn != nil {
		fn()
	}
	return nil
}

func (c *httpcConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		c.idle = time.AfterFunc(d, func() { c.Close() })
	}
	return nil
}

// SetWriteDeadline records the deadline; armWrite is what enforces it, per write. It cannot be
// pushed to the layer below here, because that layer keeps it after this write is over — see armWrite.
func (c *httpcConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wdl.Store(0)
	} else {
		c.wdl.Store(t.UnixNano())
	}
	return nil
}
func (c *httpcConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *httpcConn) LocalAddr() net.Addr  { return c.la }
func (c *httpcConn) RemoteAddr() net.Addr { return c.ra }

// chromeClientHints is the Client Hints / Fetch Metadata block Chrome attaches to EVERY same-origin
// fetch; no Chrome has omitted it since 89. The brand list and the platform have to agree with
// chromeUA or the block is a new contradiction rather than a fix — TestClientHintsMatchTheUA pins that.
var chromeClientHints = [][2]string{
	{"sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`},
	{"sec-ch-ua-mobile", "?0"},
	{"sec-ch-ua-platform", `"Windows"`},
	{"Sec-Fetch-Dest", "empty"},
	{"Sec-Fetch-Mode", "cors"},
	{"Sec-Fetch-Site", "same-origin"},
}

// browserHeaders dresses a POST-ladder request as an ordinary page fetch, matching the Chrome
// ClientHello uEdgeHandshake presents on that path. Accept-Encoding is set EXPLICITLY: unset, Go's
// transport adds its own lone "gzip", which no browser sends alone, and setting it also turns OFF Go's
// transparent decompression — hence the downstream's encoded-body refusal. Header order is not matched.
func browserHeaders(r *http.Request) {
	r.Header.Set("User-Agent", chromeUA)
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Encoding", chromeAcceptEncoding)
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Cache-Control", "no-store")
	for _, h := range chromeClientHints {
		r.Header.Set(h[0], h[1])
	}
	// Origin belongs on the POSTs and NOT on the downstream GET: per the Fetch spec a browser appends it
	// for a CORS request, and otherwise only for methods other than GET and HEAD. On both it would be a
	// header combination no Chrome produces, on the most distinctive request this carrier makes.
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL != nil && r.URL.Host != "" {
		r.Header.Set("Origin", "https://"+r.URL.Host)
	}
}

// downstreamUnusable reports whether a Content-Encoding on the downstream response means its body
// cannot be handed to the framer. browserHeaders sets Accept-Encoding by hand, which turns OFF Go's
// transparent decompression, so a real coding has to fail the dial loudly rather than feed compressed
// bytes into the AEAD. "" and "identity" both mean NOT ENCODED; case and space are not significant.
func downstreamUnusable(enc string) bool {
	e := strings.ToLower(strings.TrimSpace(enc))
	return e != "" && e != "identity"
}

// grpcHeaders dresses a grpc-mode request as what it actually is: a gRPC call from a gRPC client. None
// of the browser headers belong here — Accept-Language beside Content-Type: application/grpc is a
// combination no client produces. The call-shaped headers themselves are set in dialHTTPCGrpc.
func grpcHeaders(r *http.Request) {
	r.Header.Set("User-Agent", grpcUA)
	r.Header.Set("grpc-accept-encoding", grpcAcceptEncoding)
}

func randSID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func httpcPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	return p
}

// --- client: POST-ladder upstream --------------------------------------------------------------

type seqChunk struct {
	seq  uint64
	data []byte
}

// POST-ladder upstream sizing. Every batch costs one full HTTP round-trip, so upWorkers × maxUpBatch is
// what is IN FLIGHT (capacity ≈ in-flight / RTT) while upChanCap + upWorkCap×maxUpBatch is what is
// WAITING — pure latency, with no priority lane for a keepalive, since the obfs length mask forbids
// reordering. The per-CDN ceiling is requests per second from one address; upMinGap paces that in TIME.
var (
	// maxUpBatch caps how many bytes the batcher coalesces into ONE upstream POST. Batching amortizes
	// the per-POST round-trip: without it each ~MTU datagram cost a full HTTP request through the CDN.
	maxUpBatch = 128 << 10
	// upWorkers is how many batches may be POSTing at once. Also the parallel-request count a CDN
	// sees, so it stays in the range a browser plausibly opens to one host — not a number to raise
	// freely for throughput.
	upWorkers = 8
	// upChanCap is the write queue in chunks, sized to hold exactly ONE full batch (the batcher drains
	// whatever is already queued, so it cannot coalesce more than this) and no more. Bigger is not a
	// buffer, it is standing latency. 1400 = the usual TUN MTU, i.e. one chunk.
	upChanCap = maxUpBatch/1400 + 2
	// upIdleConns must exceed upWorkers so a finished POST's connection is kept instead of closed —
	// otherwise every other POST pays a fresh TCP+TLS handshake through the CDN. The streaming GET
	// holds one of these too.
	upIdleConns = upWorkers * 2
	// upMinGap is the minimum time between two batch dispatches — an RTT-independent ceiling on requests
	// per second. Zero (the default) paces nothing, and it only ever DELAYS a dispatch when one happened
	// recently, so an idle link still posts at once while under load the wait lets the next batch grow.
	upMinGap time.Duration
)

// upWorkCap is how many coalesced batches may wait for a free worker. One, so the batcher blocks (and
// through it write(), and through that the TUN reader) instead of building a queue: with all workers
// busy the pipe is already full and queueing only adds delay.
const upWorkCap = 1

// SetHTTPUpstream sizes the POST-ladder upstream for the CDN this tunnel fronts through. Zero leaves a
// value at its default. Safe as package state for the same reason ApplyTuning is: one tnl-core process
// serves exactly ONE tunnel and this runs once at startup, before any carrier is built.
func SetHTTPUpstream(workers, batchKB, ratePerSec int) {
	if workers > 0 {
		upWorkers = tclamp(workers, 1, 16)
		upIdleConns = upWorkers * 2
	}
	if batchKB > 0 {
		// stays well under maxPostBody, the server's per-POST read cap — a batch over it is truncated,
		// and a truncated length-prefixed AEAD chunk desyncs the stream rather than failing cleanly.
		maxUpBatch = tclamp(batchKB, 8, 512) << 10
		upChanCap = maxUpBatch/1400 + 2
	}
	if ratePerSec > 0 {
		upMinGap = time.Second / time.Duration(tclamp(ratePerSec, 1, 1000))
	}
}

// httpcUp is the client's POST-ladder upstream. Writes are copied and queued; one batcher coalesces
// them into a single POST per batch (each tagged with a monotonic seq so the server reassembles in
// order) and hands it to a small worker pool. Short discrete POSTs are what a CDN forwards at once
// where it would buffer one long streaming body. Any POST failure fails the whole conn, once.
type httpcUp struct {
	hc     *http.Client
	ctx    context.Context
	urlFor func(seq uint64) string
	setHdr func(*http.Request)
	seq    uint64        // batch sequence; assigned only by the single batcher goroutine, so no atomic needed
	ch     chan []byte   // raw upstream byte chunks from write()
	work   chan seqChunk // coalesced, seq-tagged batches ready to POST
	// The upstream shape is snapshotted here, never read from the goroutines: SetHTTPUpstream writes
	// these globals, and a batcher looping on the live maxBatch (or a worker reading the live timeout)
	// is a data race against it — the queue sizes below are already fixed at construction anyway, so
	// re-reading the cap mid-flight could only ever disagree with them.
	minGap   time.Duration // snapshot of upMinGap
	maxBatch int           // snapshot of maxUpBatch
	postTO   time.Duration // snapshot of upPostTimeout
	fail     func()
	once     sync.Once
}

func newHTTPCUp(ctx context.Context, hc *http.Client, urlFor func(uint64) string, setHdr func(*http.Request), fail func()) *httpcUp {
	u := &httpcUp{hc: hc, ctx: ctx, urlFor: urlFor, setHdr: setHdr, fail: fail,
		ch: make(chan []byte, upChanCap), work: make(chan seqChunk, upWorkCap),
		minGap: upMinGap, maxBatch: maxUpBatch, postTO: upPostTimeout}
	go u.batcher()
	for i := 0; i < upWorkers; i++ {
		go u.worker()
	}
	return u
}

// write queues one upstream chunk, honouring the caller's write deadline (unix-nanos, 0 = none). The
// deadline matters because this enqueue parks forever whenever the far edge stops answering: the
// workers block in post, work fills, the batcher blocks, ch fills. It is reached from writeFrame UNDER
// cf.mu, so parking here freezes the tunnel's TUN reader and its keepalive loop with it.
func (u *httpcUp) write(p []byte, deadline int64) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	if deadline == 0 {
		select {
		case u.ch <- b:
			return len(p), nil
		case <-u.ctx.Done():
			return 0, io.ErrClosedPipe
		}
	}
	t := time.NewTimer(time.Until(time.Unix(0, deadline)))
	defer t.Stop()
	select {
	case u.ch <- b:
		return len(p), nil
	case <-u.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-t.C:
		return 0, os.ErrDeadlineExceeded
	}
}

// batcher coalesces queued write chunks into one POST body up to maxUpBatch, tagging each batch with a
// monotonic seq so the server reassembles in order. It blocks for the first chunk, then drains whatever
// is ALREADY queued — an idle link posts one chunk at once, a burst posts a big batch. One goroutine,
// so seq stays strictly in byte order. A chunk that would push past maxUpBatch is CARRIED to the next.
func (u *httpcUp) batcher() {
	var carry []byte
	var lastSend time.Time
	for {
		var buf []byte
		if carry != nil {
			buf, carry = carry, nil
		} else {
			select {
			case buf = <-u.ch:
			case <-u.ctx.Done():
				return
			}
		}
	drain:
		for len(buf) < u.maxBatch {
			select {
			case more := <-u.ch:
				if len(buf)+len(more) > u.maxBatch {
					carry = more // next batch starts with it; order is preserved either way
					break drain
				}
				buf = append(buf, more...)
			case <-u.ctx.Done():
				return
			default:
				break drain
			}
		}
		if u.minGap > 0 { // request-rate ceiling: wait out the gap, which also grows the next batch
			if d := u.minGap - time.Since(lastSend); d > 0 && !lastSend.IsZero() {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-u.ctx.Done():
					t.Stop()
					return
				}
			}
			lastSend = time.Now()
		}
		seq := u.seq
		u.seq++
		select {
		case u.work <- seqChunk{seq, buf}:
		case <-u.ctx.Done():
			return
		}
	}
}

func (u *httpcUp) worker() {
	for {
		select {
		case <-u.ctx.Done():
			return
		case sc := <-u.work:
			if err := u.post(sc); err != nil {
				u.once.Do(u.fail) // kill the conn once; dialLoop re-dials a fresh session
				return
			}
		}
	}
}

// upPostTimeout bounds ONE upstream POST end to end. Without it the only bound on hc.Do is the session
// ctx, i.e. none: an edge that accepts the body and then never answers holds a worker forever, and
// upWorkers of those hold the whole ladder. Generous on purpose — a failed POST forces a re-dial, so
// tripping it on a merely slow path would cost more than the stall it prevents.
var upPostTimeout = writeTimeout

func (u *httpcUp) post(sc seqChunk) error {
	ctx, cancel := context.WithTimeout(u.ctx, u.postTO)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", u.urlFor(sc.seq), bytes.NewReader(sc.data))
	if err != nil {
		return err
	}
	u.setHdr(req)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := u.hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("httpc: up seq %d got HTTP %d", sc.seq, resp.StatusCode)
	}
	return nil
}

// httpcEdge resolves the (dialAddr, host, ech, path) for this attempt. With an edge pool it uses
// the pool's current (IP × SNI); current() never dead-ends (it falls back to the least-bad combo).
// A single fixed edge uses the plain WSHost/WSECH/WSPath.
func (b *TCP) httpcEdge() (dialAddr, host string, ech []byte, path string, err error) {
	dialAddr, host, ech, path = b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			return "", "", nil, "", fmt.Errorf("httpc: edge pool is empty")
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	return dialAddr, host, ech, path, nil
}

// establishHTTPC (client) opens a fresh HTTP-carrier session to the edge and returns a net.Conn over it.
// Both upstream styles share the same fronting (TLS+ECH mirror wss) and the same pool rotation: post
// (default) is a long-lived downstream GET plus short seq-tagged POSTs, the most CDN-compatible shape;
// grpc is one full-duplex request presented as a real gRPC call, which needs HTTP/2 to the edge.
func (b *TCP) establishHTTPC() (net.Conn, string, string, error) {
	dialAddr, host, ech, path, err := b.httpcEdge()
	if err != nil {
		return nil, "", "", err
	}
	conn, err := b.dialHTTPCOnce(dialAddr, host, ech, path, handshakeTimeout)
	// In-band ECH self-heal (mirrors the ws carrier's tlsToEdge): once the config we hold goes stale EVERY
	// edge rejects ECH until a rebuild. The rejection carries a fresh RetryConfigList, so redial ONCE with
	// it before blaming the edge. errors.As reaches the *utls.ECHRejectionError through the Do error chain.
	if err != nil && b.wsTLS && len(ech) > 0 {
		var echErr *utls.ECHRejectionError
		if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList
			log.Printf("core/http: ECH self-heal for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			conn, err = b.dialHTTPCOnce(dialAddr, host, ech, path, handshakeTimeout)
			if err == nil { // self-heal succeeded: persist the fresh key and surface it (pool or single-edge)
				b.noteECHSelfHeal(host, ech)
			}
		}
	}
	// Neither outcome touches health. A dial that FAILED burns nothing and a dial that CAME UP clears
	// nothing: an established carrier proves the control path, not that data crosses it, and this pool
	// spent its history mistaking the first for the second. The node's tun probe is the only judge, on
	// both pools and in both directions.
	combo := ""
	if err == nil {
		combo = activeLabel(dialAddr, host)
	}
	return conn, dialAddr, combo, err
}

// dialHTTPCOnce builds a fresh transport/client/context for ONE attempt against (dialAddr, host, ech,
// path) and opens the session in the configured mode. Each attempt needs its own transport, since the
// ECH lives in tr.TLSClientConfig. On error, everything this attempt allocated is already torn down.
func (b *TCP) dialHTTPCOnce(dialAddr, host string, ech []byte, path string, budget time.Duration) (net.Conn, error) {
	single := b.httpcMode == "grpc" // one full-duplex request over h2
	h2 := single && b.wsTLS         // grpc over wss rides HTTP/2 to the edge

	// rawDial always targets the fixed edge, regardless of the request URL host, so the Host/SNI
	// stays the fronting domain while we connect to a specific (clean) CDN IP.
	// The CONNECT gets its own, much smaller budget: `budget` covers the whole attempt (connect + TLS +
	// request), and letting the connect eat all of it means a dead edge holds the attempt for the full
	// window while a live one answers in ~115ms. The ctx still bounds the total, so this only ever
	// shortens — never lengthens — what an attempt may take. Same number the ws shape uses.
	rawDial := func(ctx context.Context) (net.Conn, error) {
		d := budget
		if d > connectTimeout {
			d = connectTimeout
		}
		return b.dialer(d).DialContext(ctx, "tcp", dialAddr)
	}

	// Track every underlying TCP conn this attempt dials so teardown can FORCE them shut. The h2 path is
	// the one that matters: x/net/http2 multiplexes the whole session over ONE conn and answers our
	// cancellation with RST_STREAM only, while CloseIdleConnections races the async stream teardown — so a
	// retired conn can linger, and over hours of rotation that leaks fds until no new dial can be made.
	var dialedMu sync.Mutex
	var dialed []net.Conn
	track := func(c net.Conn) net.Conn {
		if c != nil {
			dialedMu.Lock()
			dialed = append(dialed, c)
			dialedMu.Unlock()
		}
		return c
	}
	forceClose := func() {
		dialedMu.Lock()
		conns := dialed
		dialed = nil
		dialedMu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	}

	var rt http.RoundTripper
	var closeIdle func()
	if b.wsTLS && b.httpcTLS == nil {
		// Production TLS, done here via DialTLSContext so the transport never runs its own. The POST ladder
		// wears the ws carrier's Chrome fingerprint and rides http/1.1 (force that ALPN): those requests
		// really are shaped like page fetches. grpc mode does not — it presents Go's own ClientHello,
		// matching the grpc-go User-Agent the request carries, and offers only h2, exactly as grpc-go does.
		var alpn []string
		if h2 {
			alpn = []string{"h2"}
		} else {
			alpn = []string{"http/1.1"}
		}
		dialTLS := func(ctx context.Context) (net.Conn, error) {
			c, err := rawDial(ctx)
			if err != nil {
				return nil, err
			}
			// Bound the handshake. Transport.TLSHandshakeTimeout does NOT apply when the caller supplies
			// DialTLSContext, so without this an edge that completes TCP and then stalls mid-ClientHello parks
			// the dial indefinitely. The budget is PASSED IN rather than armed on the socket here, because
			// uEdgeHandshake arms the deadline itself; cleared on success, since h2 then owns the conn.
			uc, err := uEdgeHandshake(b.fragWrap(c, host, ech), host, ech, alpn, h2, budget) // split the ClientHello SNI when enabled
			if err != nil {
				c.Close()
				return nil, err
			}
			_ = c.SetDeadline(time.Time{})
			track(c) // remember the raw fd so teardown can force it shut (h2 won't on its own)
			return uc, nil
		}
		if h2 {
			// x/net/http2 speaks h2 directly over the uTLS conn: it only reads TLS state / *tls.Conn
			// via guarded assertions, so a *utls.UConn is accepted (it just skips those extras).
			h2t := &http2.Transport{
				DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return dialTLS(ctx)
				},
				// grpc-go frames HTTP/2 itself and sends no Accept-Encoding; Go's transport would add
				// "accept-encoding: gzip" on our behalf, which is another header no gRPC client sends.
				// We also never want transparent decompression on a binary stream.
				DisableCompression: true,
			}
			rt, closeIdle = h2t, func() { h2t.CloseIdleConnections(); forceClose() }
		} else {
			tr := &http.Transport{
				DialTLSContext:      func(ctx context.Context, _, _ string) (net.Conn, error) { return dialTLS(ctx) },
				MaxIdleConns:        upIdleConns * 2,
				MaxIdleConnsPerHost: upIdleConns, // the GET holds one of these; the upstream POSTs reuse the rest
				IdleConnTimeout:     90 * time.Second,
			}
			rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
		}
	} else {
		// No TLS (plain http), or a test that overrides the edge TLS wholesale (httpcTLS). The
		// transport runs its own TLS (Go's) on a raw-dialed conn.
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, err := rawDial(ctx)
				if err != nil {
					return nil, err
				}
				if b.wsTLS {
					c = b.fragWrap(c, host, ech)
				}
				return track(c), nil
			},
			ForceAttemptHTTP2:   h2,
			DisableCompression:  h2, // grpc: no Accept-Encoding, same as the production h2 transport
			MaxIdleConns:        upIdleConns * 2,
			MaxIdleConnsPerHost: upIdleConns,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: budget,
		}
		if b.wsTLS {
			tr.TLSClientConfig = b.httpcTLS
		}
		rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
	}

	scheme := "http"
	if b.wsTLS {
		scheme = "https"
	}
	sid := randSID()
	base := scheme + "://" + host + httpcPath(path)
	hc := &http.Client{Transport: rt}
	ctx, cancel := context.WithCancel(context.Background())
	setHdr := browserHeaders
	if b.httpcMode == "grpc" {
		setHdr = grpcHeaders
	}
	// Only two modes: grpc (one full-duplex request) and post (default). Plain stream-one
	// (octet-stream) was removed because it stalled through CDNs that buffer the origin leg.
	var conn net.Conn
	var err error
	switch b.httpcMode {
	case "grpc":
		conn, err = b.dialHTTPCGrpc(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr, budget)
	default:
		conn, err = b.dialHTTPCPost(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr, budget)
	}
	if err != nil {
		// A FAILED establish (dial ok but header timeout / non-200 / write error) has cancelled the
		// ctx but does not own a closeFn, so nothing would force-close a conn it already dialed — that
		// is the same h2 leak, just on the failure path (a repeatedly-failing edge would bleed fds).
		// Reap it here; on success closeFn owns this instead.
		closeIdle()
	}
	return conn, err
}

// doWithHeaderTimeout runs hc.Do but bounds the wait for the response to BEGIN (headers received), not
// the streaming body that follows: the request context governs the whole session body, so it cannot
// also bound this establishment step. On timeout the caller cancels the session ctx, which unblocks the
// parked goroutine — it returns into the buffered channel, so nothing leaks.
func doWithHeaderTimeout(hc *http.Client, req *http.Request, d time.Duration) (*http.Response, error) {
	type doRes struct {
		resp *http.Response
		err  error
	}
	ch := make(chan doRes, 1)
	go func() { r, e := hc.Do(req); ch <- doRes{r, e} }()
	select {
	case r := <-ch:
		return r.resp, r.err
	case <-time.After(d):
		return nil, fmt.Errorf("httpc: response-header timeout (%s)", d)
	}
}

// --- gRPC framing (mode "grpc") ---------------------------------------------------------------
//
// gRPC rides one full-duplex request but presents as a real gRPC call, so a CDN treats it as gRPC and
// streams it to the origin over h2c instead of buffering the request body. On the wire: Content-Type
// application/grpc, and each frame is a gRPC length-prefixed message [0][uint32 len][msg] where msg is
// a minimal protobuf Hunk {bytes data = 1} carrying the payload.

const grpcMaxMsg = 1 << 20 // reject an oversized length prefix (hostile/broken peer)

// grpcFrame wraps one payload as a gRPC message: [0][uint32 msgLen] + protobuf(field 1 = payload).
func grpcFrame(p []byte) []byte {
	hunk := make([]byte, 0, 1+binary.MaxVarintLen64)
	hunk = append(hunk, 0x0a) // field 1, wire type 2 (length-delimited)
	hunk = binary.AppendUvarint(hunk, uint64(len(p)))
	msgLen := len(hunk) + len(p)
	buf := make([]byte, 5+msgLen)
	buf[0] = 0 // not compressed
	binary.BigEndian.PutUint32(buf[1:5], uint32(msgLen))
	n := copy(buf[5:], hunk)
	copy(buf[5+n:], p)
	return buf
}

// grpcUnhunk extracts the payload from a Hunk message (field 1). A message we don't recognise as
// a Hunk is returned verbatim (defensive — both ends are our own code).
func grpcUnhunk(msg []byte) []byte {
	if len(msg) >= 1 && msg[0] == 0x0a {
		if n, adv := binary.Uvarint(msg[1:]); adv > 0 && n <= uint64(len(msg)) {
			if start, end := 1+adv, 1+adv+int(n); end <= len(msg) {
				return msg[start:end]
			}
		}
	}
	return msg
}

// grpcFramingWriter wraps each Write as one gRPC message on the underlying stream.
type grpcFramingWriter struct{ w io.Writer }

func (g *grpcFramingWriter) Write(p []byte) (int, error) {
	if _, err := g.w.Write(grpcFrame(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// grpcDeframingReader reassembles gRPC messages from the underlying stream and yields their
// unwrapped payloads. A message can span several underlying reads; leftover payload is buffered.
type grpcDeframingReader struct {
	r   io.Reader
	buf []byte
}

func (g *grpcDeframingReader) Read(p []byte) (int, error) {
	for len(g.buf) == 0 {
		var hdr [5]byte
		if _, err := io.ReadFull(g.r, hdr[:]); err != nil {
			return 0, err
		}
		// hdr[0] is gRPC's per-message COMPRESSED flag. This is the grpc twin of the POST ladder's
		// Content-Encoding guard: the body IS the data plane, so a compressed message opens as garbage under
		// the AEAD and the tunnel comes up delivering nothing. We advertise grpc-accept-encoding: gzip as
		// camouflage and never compress ourselves, which makes a set flag someone else's doing by definition.
		if hdr[0] != 0 {
			return 0, fmt.Errorf("http/grpc: message came back compressed (flag %d) — this path compresses gRPC "+
				"messages, which the carrier cannot decode; turn message compression off for it at the CDN", hdr[0])
		}
		msgLen := binary.BigEndian.Uint32(hdr[1:5])
		if msgLen > grpcMaxMsg {
			return 0, fmt.Errorf("http/grpc: message too large (%d)", msgLen)
		}
		if msgLen == 0 {
			continue
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(g.r, msg); err != nil {
			return 0, err
		}
		g.buf = grpcUnhunk(msg)
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	return n, nil
}

// Close unblocks a Read parked in io.ReadFull by closing the underlying reader.
func (g *grpcDeframingReader) Close() error {
	if c, ok := g.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// dialHTTPCGrpc (grpc) is stream-one dressed as a gRPC call: one full-duplex POST with
// Content-Type application/grpc and gRPC message framing on both directions.
func (b *TCP) dialHTTPCGrpc(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request), budget time.Duration) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", base+"?s="+sid, pr)
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	setHdr(req)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	// No grpc-encoding: grpc-go sets it only when it is actually compressing, so "identity" on the wire is
	// a small tell of a hand-rolled client. Nothing needs it — the authority is each message's own 5-byte
	// prefix, which grpcDeframingReader reads.
	req.ContentLength = -1
	resp, err := doWithHeaderTimeout(hc, req, httpcHeaderWait(budget))
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		pw.Close()
		// A 403 from the EDGE has one overwhelmingly likely cause and the bare status hid it: the
		// Content-Type: application/grpc header ALONE draws it, which matches Cloudflare requiring gRPC to
		// be switched on per zone before it will carry it. Other edges answer the same shape 200, so this is
		// not universal and nothing here is wrong with the carrier — the operator has a switch to flip.
		if resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("http/grpc: the CDN edge refused the gRPC request with HTTP 403 — "+
				"measured on a live edge, this is the Content-Type: application/grpc header alone, and "+
				"Cloudflare needs gRPC enabled on the zone (Network -> gRPC) before it will proxy it. "+
				"Turn it on for %s, or use the plain ws / http carrier shape instead", dialAddr)
		}
		return nil, fmt.Errorf("http/grpc: got HTTP %d (want 200)", resp.StatusCode)
	}
	conn := &httpcConn{
		r:  &grpcDeframingReader{r: resp.Body}, // Read <- deframed downstream
		w:  &grpcFramingWriter{w: pw},          // Write -> framed -> pipe -> request body (upstream)
		ra: strAddr(dialAddr), la: strAddr("http-client"),
	}
	conn.closeFn = func() { cancel(); pw.Close(); resp.Body.Close(); closeIdle() }
	return conn, nil
}

// dialHTTPCPost (post) opens the long-lived downstream GET and starts the POST-ladder
// upstream sender for a fresh session, returning a net.Conn over the pair.
func (b *TCP) dialHTTPCPost(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request), budget time.Duration) (net.Conn, error) {
	greq, err := http.NewRequestWithContext(ctx, "GET", base+"?s="+sid, nil)
	if err != nil { // a malformed host/path would otherwise nil-deref inside doWithHeaderTimeout's goroutine
		cancel()
		return nil, err
	}
	setHdr(greq)
	gresp, err := doWithHeaderTimeout(hc, greq, httpcHeaderWait(budget))
	if err != nil {
		cancel()
		return nil, err
	}
	if gresp.StatusCode != http.StatusOK {
		gresp.Body.Close()
		cancel()
		return nil, fmt.Errorf("httpc: down got HTTP %d (want 200)", gresp.StatusCode)
	}
	// The downstream body IS the data plane, and browserHeaders' explicit Accept-Encoding disables Go's
	// transparent decompression — so an edge that compresses this response anyway feeds compressed bytes
	// to the framer. Refuse loudly and by name: the dial fails, the pool treats the edge as bad, and the
	// operator gets the knob to turn instead of a tunnel that connects and delivers nothing.
	if enc := gresp.Header.Get("Content-Encoding"); downstreamUnusable(enc) {
		gresp.Body.Close()
		cancel()
		return nil, fmt.Errorf("httpc: down came back %s-encoded — this edge compresses the downstream, "+
			"which the carrier cannot decode; turn compression off for this path at the CDN", enc)
	}
	urlFor := func(seq uint64) string {
		return base + "?s=" + sid + "&seq=" + strconv.FormatUint(seq, 10)
	}
	conn := &httpcConn{
		r:  gresp.Body,
		ra: strAddr(dialAddr), la: strAddr("http-client"),
	}
	conn.closeFn = func() { cancel(); gresp.Body.Close(); closeIdle() }
	conn.up = newHTTPCUp(ctx, hc, urlFor, setHdr, func() { conn.Close() })
	return conn, nil
}

// --- server ----------------------------------------------------------------------------------

type httpcSession struct {
	upR   *io.PipeReader
	upW   *io.PipeWriter
	done  chan struct{}
	start sync.Once
	end   sync.Once

	upMu    sync.Mutex        // orders upstream POSTs by seq before writing to the upstream pipe
	nextSeq uint64            // next seq we expect to hand to upW
	pend    map[uint64][]byte // out-of-order chunks waiting for the gap to fill
	pendLen int               // bytes currently held in pend — bounded by maxPendBytes()
}

// httpcGetOrCreate returns the session for sid, creating it (with a fresh upstream pipe and a
// watchdog that reaps a session whose GET never arrives) on first sight. ONLY the downstream GET
// may create: see httpcLookup.
func (b *TCP) httpcGetOrCreate(sid string) *httpcSession {
	b.httpcMu.Lock()
	defer b.httpcMu.Unlock()
	if s := b.httpcSessions[sid]; s != nil {
		return s
	}
	pr, pw := io.Pipe()
	s := &httpcSession{upR: pr, upW: pw, done: make(chan struct{}), pend: map[uint64][]byte{}}
	b.httpcSessions[sid] = s
	return s
}

// httpcLookup returns an EXISTING session, or nil. The upstream POST path uses this instead of
// httpcGetOrCreate: a real client opens the downstream GET first and only builds its upstream sender
// once that GET's response head has arrived, so by the time it can post a chunk the session exists.
// Letting a POST create one lets anyone who can reach the origin allocate a pipe per invented id.
func (b *TCP) httpcLookup(sid string) *httpcSession {
	b.httpcMu.Lock()
	defer b.httpcMu.Unlock()
	return b.httpcSessions[sid]
}

// maxPendBytes bounds the out-of-order upstream buffer of ONE session in BYTES; the 1024-entry gap
// guard bounds only the entry COUNT, which at a 1 MiB maxPostBody is ~1 GiB. A legitimate client has
// at most upWorkers batches of maxUpBatch in flight, so twice that covers any real reordering, and the
// 4 MiB floor keeps a deliberately tuned-down client from clipping itself on a lossy path.
func maxPendBytes() int {
	if n := 2 * upWorkers * maxUpBatch; n > 4<<20 {
		return n
	}
	return 4 << 20
}

// deliver feeds one upstream chunk into the ordered upstream. Out-of-order chunks are buffered until
// the gap fills; already-delivered seqs are dropped. Writes happen under upMu so the byte stream stays
// ordered with several POSTs in flight. It REPORTS whether the chunk is now the server's to deliver,
// because the caller answers the POST and a 204 is a promise that the bytes are in the stream.
func (s *httpcSession) deliver(seq uint64, data []byte) bool {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	if seq < s.nextSeq {
		// Already delivered. A re-POST of a seq we consumed is a legitimate retransmit and its bytes
		// ARE in the stream, so this is a success: answering it with an error would make the client
		// tear down a healthy session over a duplicate.
		return true
	}
	// Runaway gap (a lost POST) — let the client fail + re-dial. Bounded on BOTH axes: the entry
	// count, and the bytes those entries hold. A chunk is up to maxPostBody, so the count alone let
	// a stranger park ~1 GiB here by posting sparse seqs that never fill the gap at nextSeq.
	if len(s.pend) > 1024 || s.pendLen+len(data) > maxPendBytes() {
		return false
	}
	if old, ok := s.pend[seq]; ok {
		s.pendLen -= len(old) // a re-POST of a seq still waiting: replaces, doesn't add
	}
	s.pend[seq] = data
	s.pendLen += len(data)
	for {
		d, ok := s.pend[s.nextSeq]
		if !ok {
			break
		}
		delete(s.pend, s.nextSeq)
		s.pendLen -= len(d)
		s.nextSeq++
		if len(d) > 0 {
			if _, err := s.upW.Write(d); err != nil {
				return false // session gone — the client must re-dial, not keep posting into it
			}
		}
	}
	return true
}

func (s *httpcSession) close(b *TCP, sid string) {
	s.end.Do(func() {
		close(s.done)
		s.upW.Close()
		s.upR.Close()
		b.httpcMu.Lock()
		delete(b.httpcSessions, sid)
		b.httpcMu.Unlock()
	})
}

// newHTTPCServerConn builds the server side of one httpc session over a ResponseWriter. Both server
// shapes go through here so the write deadline is wired from exactly one place: a conn built without
// setWD silently reverts to a recorded-but-unenforced deadline. rd/wr are the session's byte streams,
// which differ per shape, while w is the ResponseWriter underneath — the only handle able to interrupt.
func newHTTPCServerConn(w http.ResponseWriter, rd io.Reader, wr io.Writer, flush func(), remote string, closeFn func()) *httpcConn {
	return &httpcConn{
		r: rd, w: wr, flush: flush,
		setWD:   http.NewResponseController(w).SetWriteDeadline,
		ra:      strAddr(remote),
		la:      strAddr("http-server"),
		closeFn: closeFn,
	}
}

// serveHTTPCGrpc handles a gRPC-framed full-duplex request: the single request IS the session, the
// body carries gRPC message framing and the response
// presents as gRPC (Content-Type application/grpc + a grpc-status trailer on clean close), so a
// CDN proxies it as a gRPC call (h2c to the origin, streamed, not buffered).
func (b *TCP) serveHTTPCGrpc(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-encoding", "identity")
	w.Header().Set("Trailer", "grpc-status") // announced now, set after the body on clean close
	w.WriteHeader(http.StatusOK)
	fl.Flush() // send the response head now so the client's request returns and the duplex opens
	conn := newHTTPCServerConn(w, &grpcDeframingReader{r: r.Body}, &grpcFramingWriter{w: w}, fl.Flush, r.RemoteAddr, nil)
	b.handleServerConn(conn) // the request lifetime IS the session; blocks until it ends
	conn.Close()
	w.Header().Set("grpc-status", "0") // OK (trailer)
}

// httpcHandler routes a session's requests by shape. grpc is a single full-duplex POST with
// Content-Type application/grpc. post uses a GET (downstream body, drives handleServerConn
// once) plus seq-tagged POSTs (?seq=N) fed into the upstream. The server auto-detects the style
// per request, so a grpc client and a packet client both work against one endpoint.
func (b *TCP) httpcHandler(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	if len(sid) != 32 || strings.Trim(sid, "0123456789abcdef") != "" {
		http.Error(w, "Not Found", http.StatusNotFound) // a probe/scanner sees a plain 404
		return
	}
	// grpc: a single full-duplex POST presenting as a gRPC call (Content-Type application/grpc).
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		b.serveHTTPCGrpc(w, r)
		return
	}
	if r.Method == http.MethodPost {
		// An upstream chunk is only ever accepted for a session the downstream GET already opened.
		// An unknown id gets the same plain 404 a probe sees, so nothing is allocated for a caller
		// that has not been through the GET — the only path that can create a session.
		s := b.httpcLookup(sid)
		if s == nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		data, rerr := io.ReadAll(io.LimitReader(r.Body, maxPostBody))
		if rerr != nil {
			// A truncated body must NOT be delivered. Upstream is a length-prefixed AEAD stream, so a short
			// chunk at seq N shifts every following byte and the desync cascades long after the truncation.
			// Answering 204 ("chunk accepted") makes it worse — the client never learns and never re-dials.
			// Dropping it is self-correcting: deliver()'s gap guard stalls at nextSeq and forces the re-dial.
			log.Printf("core/http: truncated upstream chunk seq=%d (%d bytes read): %v — dropping so the client re-dials", seq, len(data), rerr)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if !s.deliver(seq, data) {
			// The chunk was THROWN AWAY: the pending map hit its entry or byte cap, or the upstream pipe is
			// gone. 204 means "chunk accepted", so answering it for a chunk nobody has stalls the stream at
			// nextSeq forever while the downstream GET keeps streaming. A non-2xx fails the POST worker, which
			// fails the conn and forces the re-dial that can refill the gap. A duplicate is not this case.
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent) // 204: chunk accepted, session stays open
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	// The Flusher assertion comes BEFORE the create. This is the only place a session can be created and
	// close(s.done) is a few statements below it, so putting the one statement that can bail out ahead of
	// the create makes a created-but-never-served session impossible rather than merely unlikely.
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	s := b.httpcGetOrCreate(sid) // the GET is the only path that may create a session
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // ask any nginx/CDN in front not to buffer
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	conn := newHTTPCServerConn(w, s.upR, w, fl.Flush, r.RemoteAddr, func() { s.close(b, sid) })
	// Drive the authenticated core session once (the GET owns the downstream writer).
	s.start.Do(func() { go b.handleServerConn(conn) })
	<-s.done // hold the GET open (streaming downstream) until the session ends
}

// runHTTPCServer serves the HTTP-carrier endpoint until Close. A non-matching path/probe gets a plain
// 404 from the handler, so the port looks like an ordinary idle web endpoint.
func (b *TCP) runHTTPCServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.httpcHandler)
	// Wrap in an h2c handler so a CDN can reach us over HTTP/2 cleartext. Cloudflare connects to
	// the origin with h2c when gRPC is enabled — that is the leg that STREAMS a full-duplex call
	// instead of buffering the request body (which stalls stream-one over a plain HTTP/1.1 origin).
	// h2c falls through to HTTP/1.1 for the POST ladder, so every mode shares this one plaintext listener.
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	b.httpSrv.Store(srv) // publish atomically so Close (another goroutine) sees it without a data race
	if err := srv.Serve(b.ln); err != nil && !b.closed.Load() {
		log.Printf("core/http: server: %v", err)
	}
}
