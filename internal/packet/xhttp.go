// xhttp carrier: the core stream rides plain HTTP requests instead of a WebSocket upgrade, so
// it passes through CDNs that block or don't proxy WebSocket (e.g. a Cloudflare account with
// WebSocket disabled) while still looking like ordinary HTTPS.
//
//	downstream (server -> client): one long-lived GET whose streaming response body carries
//	                               the sealed frames.
//	upstream   (client -> server): PACKET-UP — each write is a short, discrete POST carrying one
//	                               chunk plus a monotonic seq. A CDN like Cloudflare buffers a
//	                               single long streaming request body (which stalled the
//	                               handshake), but forwards short complete POSTs immediately; the
//	                               server reassembles them by seq into the upstream byte stream.
//	correlation: a random session id in the query ties the GET and the POSTs together.
//
// Both directions present a byte stream, so xhttpConn is a net.Conn and the existing connFramer
// (length-prefix + AEAD + obfs + keepalive) rides on top unchanged — exactly as over raw TCP, a
// TLS-cover, or a WebSocket conn. The same fronting fields as ws apply (host/edge/ECH/path); the
// server stays plain (the CDN terminates TLS).
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

// chromeUA is the browser User-Agent presented by the ws AND xhttp carriers (single source of truth).
// Its Chrome MAJOR version MUST match the uTLS ClientHello parrot (utls.HelloChrome_Auto — currently
// Chrome 133) — otherwise the JA3/JA4 computed on the TLS handshake and the app-layer UA advertise
// different Chrome versions, a combination no real browser produces and thus a cheap fingerprint.
// TestUserAgentMatchesTLSParrot fails the build if the two drift apart (e.g. after a uTLS bump).
const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// maxXhChunk caps a single upstream POST body so a hostile client can't force a huge alloc.
const maxXhChunk = 1 << 20

// xhttpEstablishTimeout bounds the wait for the establishing request's response HEADERS (the
// downstream GET, or the grpc POST). TCP dial and the TLS handshake are each already bounded
// (10s + TLSHandshakeTimeout); this covers the otherwise-unbounded wait for the edge to START
// streaming. A CDN that completes TCP+TLS but never streams the origin leg (a throttled origin,
// a half-open grpc call, a stale-ECH edge that Cloudflare still TLS-terminates) must not block
// establishment forever — that stall is what freezes rotation and manual pin. Generous, because
// it also covers the bounded TCP+TLS phases; a healthy edge flushes headers immediately.
const xhttpEstablishTimeout = 3 * handshakeTimeout

// strAddr is a net.Addr for an xhttp conn (there is no single socket behind it).
type strAddr string

func (a strAddr) Network() string { return "xhttp" }
func (a strAddr) String() string  { return string(a) }

// xhttpConn presents the GET(down) + packet-up(POSTs) pair (client) or the reassembled upstream
// pipe + downstream ResponseWriter (server) as a single net.Conn. On the client, Write goes to
// the packet-up sender (up); on the server, Write goes to the GET response writer (w). Read
// deadlines are honoured by an idle timer that closes the conn when it fires.
type xhttpConn struct {
	r     io.Reader
	w     io.Writer
	flush func()
	up    *xhUp // client only: packet-up upstream sender (nil on the server)

	wmu     sync.Mutex
	wdl     atomic.Int64 // unix-nanos write deadline (0 = none); honoured by Write, unlike a no-op setter
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	ra, la  net.Addr
}

func (c *xhttpConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *xhttpConn) Write(p []byte) (int, error) {
	if c.up != nil { // client: each write becomes a short POST with a seq
		return c.up.write(p)
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
	// SERVER: c.w is the long-lived GET's ResponseWriter. If the client stops reading, the h2 flow
	// -control window fills and this Write parks — with no deadline of its own, forever, holding the
	// goroutine that drains the TUN. connFramer arms a write deadline before every framed write
	// expecting exactly this to be bounded (wsconn honours it); on xhttp the setter used to be a bare
	// `return nil`, so the protection silently did not exist here.
	if dl := c.wdl.Load(); dl != 0 && time.Now().UnixNano() > dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n, err := c.w.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *xhttpConn) Close() error {
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

func (c *xhttpConn) SetReadDeadline(t time.Time) error {
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

func (c *xhttpConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.wdl.Store(0)
	} else {
		c.wdl.Store(t.UnixNano())
	}
	return nil
}
func (c *xhttpConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *xhttpConn) LocalAddr() net.Addr  { return c.la }
func (c *xhttpConn) RemoteAddr() net.Addr { return c.ra }

func randSID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func xhttpPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	return p
}

// --- client: packet-up upstream --------------------------------------------------------------

type seqChunk struct {
	seq  uint64
	data []byte
}

// Packet-up upstream sizing. This is a request/response ladder — every batch costs one full HTTP
// round-trip through the CDN — so the numbers below ARE the upstream's bandwidth-delay product, and
// they were measured rather than guessed. Two separate quantities, easy to conflate:
//
//	IN FLIGHT  = upWorkers × maxUpBatch — bytes on the wire at once. This sets CAPACITY:
//	             capacity ≈ in-flight / RTT. It is not queueing delay; it is the pipe being full.
//	WAITING    = upChanCap + upWorkCap×maxUpBatch — bytes queued but not yet sent. This is pure
//	             LATENCY: a keepalive ping (and the inner TCP's acks) sit behind all of it, and the
//	             obfs length-mask keystream makes reordering illegal, so there is no priority lane —
//	             the only lever on ping is keeping this small.
//
// The old numbers had that backwards: in flight 4×32K = 128K, waiting 256 chunks + 8×32K ≈ 600K.
// So capacity was tiny AND the queue was huge. Measured in a two-netns lab with netem (both cores
// on one box, obfs+chacha20, 40–60 Mbit offered upstream):
//
//	                          RTT 150ms                    RTT 60ms
//	                  upstream   ping under load    upstream   ping under load
//	4×32K, wait 600K   4.4 Mbit   151 → 1550 ms     11.2 Mbit   60 → 518 ms
//	8×128K, wait 260K  29.7 Mbit  151 →  365 ms     57.8 Mbit   60 → 113 ms
//
// and on a deliberately slow 4 Mbit uplink (RTT 60ms) a saturating TCP flow went from 1.33 Mbit at
// 219 ms to 3.10 Mbit at 161 ms — so the wider window does NOT cost latency on a thin line: the deep
// waiting queue was the thing hurting it. Downstream (the streaming GET) was never the problem and is
// untouched: it already ran at ~60 Mbit with ping at 66 ms.
//
// Client-side only, and not a wire change: the POST framing, the seq contract and the server's
// reassembly are all unchanged, and maxUpBatch stays well under maxXhChunk (the server's per-POST read
// cap), so a new client interoperates with an old server and vice versa.
//
// THE SHAPE IS PER-CDN, because the constraint is not bandwidth — it is how many requests per second
// the CDN in front is willing to see from one address. Measured against a real ArvanCloud edge at a
// ~120ms round-trip, the same tunnel, TCP goodput up/down:
//
//	8×128K  (~70 req/s)   BANNED — the source IP is TCP-blocked for ~3.5 minutes
//	6×256K  (~55 req/s)   BANNED
//	4×512K  (~33 req/s)   4.2 / 106 Mbit    <- the sweet spot
//	4×256K  (~33 req/s)   3.7 /  86 Mbit
//	2×512K  (~18 req/s)   1.4 /  13 Mbit
//
// Two things fall out. The threshold is on the WORKER count, not on bytes — a bigger batch costs no
// extra requests, so at a fixed request budget you max the batch. And the request rate is
// workers/RTT, which means a fixed worker count is NOT portable: 4 workers is 33 req/s at 120ms but
// 133 req/s at 30ms, back in the banned range. That is what upMinGap is for — it paces dispatch in
// TIME, so the same profile behaves the same on a fast path and a slow one.
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
	// upMinGap is the minimum time between two batch dispatches — an RTT-independent ceiling on
	// requests per second. Zero (the default) paces nothing. It only ever DELAYS a dispatch when one
	// happened recently, so an idle link still posts its first chunk immediately; under load the wait
	// simply lets the next batch grow, trading request rate for batch size, which is exactly the trade
	// a WAF wants.
	upMinGap time.Duration
)

// upWorkCap is how many coalesced batches may wait for a free worker. One, so the batcher blocks (and
// through it write(), and through that the TUN reader) instead of building a queue: with all workers
// busy the pipe is already full and queueing only adds delay.
const upWorkCap = 1

// SetXHTTPUpstream sizes the packet-up upstream for the CDN this tunnel fronts through. Zero leaves a
// value at its default. Safe as package state for the same reason ApplyTuning is: one tnl-core process
// serves exactly ONE tunnel and this runs once at startup, before any carrier is built.
func SetXHTTPUpstream(workers, batchKB, ratePerSec int) {
	if workers > 0 {
		upWorkers = tclamp(workers, 1, 16)
		upIdleConns = upWorkers * 2
	}
	if batchKB > 0 {
		// stays well under maxXhChunk, the server's per-POST read cap — a batch over it is truncated,
		// and a truncated length-prefixed AEAD chunk desyncs the stream rather than failing cleanly.
		maxUpBatch = tclamp(batchKB, 8, 512) << 10
		upChanCap = maxUpBatch/1400 + 2
	}
	if ratePerSec > 0 {
		upMinGap = time.Second / time.Duration(tclamp(ratePerSec, 1, 1000))
	}
}

// xhUp is the client's packet-up upstream. Writes are copied and queued; a single batcher coalesces
// them into one POST per batch (tagging each with a monotonic seq so the server reassembles in order)
// and hands the batch to a small pool of workers that POST it as a short, complete request. Short
// discrete POSTs (not one long streaming POST a CDN would buffer) are what flow through Cloudflare;
// coalescing keeps the round-trip cost from throttling upstream throughput. Any POST failure fails the
// whole conn (once) so dialLoop re-dials a fresh session.
type xhUp struct {
	hc     *http.Client
	ctx    context.Context
	urlFor func(seq uint64) string
	setHdr func(*http.Request)
	seq    uint64        // batch sequence; assigned only by the single batcher goroutine, so no atomic needed
	ch     chan []byte   // raw upstream byte chunks from write()
	work   chan seqChunk // coalesced, seq-tagged batches ready to POST
	minGap time.Duration // snapshot of upMinGap: read once here, never from the batcher goroutine
	fail   func()
	once   sync.Once
}

func newXhUp(ctx context.Context, hc *http.Client, urlFor func(uint64) string, setHdr func(*http.Request), fail func()) *xhUp {
	u := &xhUp{hc: hc, ctx: ctx, urlFor: urlFor, setHdr: setHdr, fail: fail,
		ch: make(chan []byte, upChanCap), work: make(chan seqChunk, upWorkCap), minGap: upMinGap}
	go u.batcher()
	for i := 0; i < upWorkers; i++ {
		go u.worker()
	}
	return u
}

func (u *xhUp) write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case u.ch <- b:
		return len(p), nil
	case <-u.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

// batcher coalesces queued write chunks into one POST body up to maxUpBatch, tagging each batch with a
// monotonic seq so the server reassembles in order. It blocks for the first chunk, then drains whatever
// is ALREADY queued without waiting — so an idle link posts one chunk at once (low latency) while a
// burst posts a big batch (few round-trips). One goroutine, so seq stays strictly in byte order.
//
// A chunk that would push the batch past maxUpBatch is CARRIED to the next one rather than appended:
// the old loop tested the length before appending, so a batch could overrun the cap by one frame. That
// was invisible at a 32 KiB cap and stayed under the server's 1 MiB read limit, but it meant maxUpBatch
// was not actually a bound — raise it to the read limit and the server would truncate, which desyncs a
// length-prefixed AEAD stream rather than failing cleanly.
func (u *xhUp) batcher() {
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
		for len(buf) < maxUpBatch {
			select {
			case more := <-u.ch:
				if len(buf)+len(more) > maxUpBatch {
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

func (u *xhUp) worker() {
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

func (u *xhUp) post(sc seqChunk) error {
	req, err := http.NewRequestWithContext(u.ctx, "POST", u.urlFor(sc.seq), bytes.NewReader(sc.data))
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
		return fmt.Errorf("xhttp: up seq %d got HTTP %d", sc.seq, resp.StatusCode)
	}
	return nil
}

// xhttpEdge resolves the (dialAddr, host, ech, path) for this attempt. With an edge pool it uses
// the pool's current (IP × SNI); current() never dead-ends (it falls back to the least-bad combo).
// A single fixed edge uses the plain WSHost/WSECH/WSPath.
func (b *TCP) xhttpEdge() (dialAddr, host string, ech []byte, path string, err error) {
	dialAddr, host, ech, path = b.addr, b.wsHost, b.wsECH, b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			return "", "", nil, "", fmt.Errorf("xhttp: edge pool is empty")
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	return dialAddr, host, ech, path, nil
}

// establishXHTTP (client) opens a fresh xhttp session to the edge and returns a net.Conn over it.
// Two upstream styles share the same fronting (TLS+ECH mirror wss) and the same pool rotation
// (each attempt uses the pool's current IP × SNI; a failure burns the offending IP or SNI):
//
//	packet-up (default): a long-lived downstream GET plus short seq-tagged POSTs — most
//	                     CDN-compatible, since a CDN that buffers request bodies still forwards
//	                     short complete POSTs at once.
//	grpc (b.xhMode=="grpc"): one full-duplex request presented as a
//	                     real gRPC call — needs HTTP/2 to the edge (ws_tls) so a CDN streams it.
func (b *TCP) establishXHTTP(attribute bool) (net.Conn, string, string, error) {
	dialAddr, host, ech, path, err := b.xhttpEdge()
	if err != nil {
		return nil, "", "", err
	}
	conn, err := b.dialXHTTPOnce(dialAddr, host, ech, path)
	// In-band ECH self-heal (mirrors the ws carrier's tlsToEdge): Cloudflare rotates the ECH key
	// periodically, and once the config we hold goes stale EVERY edge rejects ECH ("tls: server
	// rejected ECH") until a rebuild — the exact production stall. The rejection carries a fresh
	// RetryConfigList; redial ONCE with it BEFORE we blame the edge, so the fleet heals from the
	// clock with no panel rebuild. errors.As reaches the *utls.ECHRejectionError (uTLS does the
	// edge handshake) through the http.Client.Do / http2 error chain — for both packet-up and grpc.
	if err != nil && b.wsTLS && len(ech) > 0 {
		var echErr *utls.ECHRejectionError
		if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList
			log.Printf("core/xhttp: ECH self-heal for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			conn, err = b.dialXHTTPOnce(dialAddr, host, ech, path)
			if err == nil { // self-heal succeeded: persist the fresh key and surface it (pool or single-edge)
				b.noteECHSelfHeal(host, ech)
			}
		}
	}
	// Attribute the outcome to the health FSM here (one place for both modes): a failure runs
	// the differential probe to decide IP vs SNI vs transient; a success clears both axes.
	// attribute is FALSE on the warm-standby build path: that differential probe fires several full
	// establishes (each bounded by xhttpEstablishTimeout), and running it in the single standby-build
	// goroutine blocks it for that whole time with standbyBuilding still set — so requestStandby()
	// no-ops, the standby never becomes ready, and proactive rotation silently freezes while the open
	// active keeps the tunnel up (the exact "rotation stopped after hours, tunnel still up" report).
	// The warm standby just retries cheaply; the retest loop attributes/heals edge health on its own.
	if b.pool != nil {
		if err != nil {
			if attribute {
				b.attributeFailure(dialAddr, wsSNIEntry{host: host, ech: ech, path: path})
			}
		} else {
			b.pool.succeeded(dialAddr, host)
		}
	}
	combo := ""
	if err == nil {
		combo = activeLabel(dialAddr, host)
	}
	return conn, dialAddr, combo, err
}

// dialXHTTPOnce builds a fresh transport/client/context for ONE attempt against (dialAddr, host,
// ech, path) and opens the session in the configured mode. Split out of establishXHTTP so a stale
// ECH rejection can be retried with a fresh config — each attempt needs its own transport, since
// the ECH lives in tr.TLSClientConfig. On error, everything this attempt allocated is already torn
// down by the dialXHTTP* helper (ctx cancelled, pipes/bodies closed).
func (b *TCP) dialXHTTPOnce(dialAddr, host string, ech []byte, path string) (net.Conn, error) {
	single := b.xhMode == "grpc" // one full-duplex request over h2
	h2 := single && b.wsTLS      // grpc over wss rides HTTP/2 to the edge

	// rawDial always targets the fixed edge, regardless of the request URL host, so the Host/SNI
	// stays the fronting domain while we connect to a specific (clean) CDN IP.
	rawDial := func(ctx context.Context) (net.Conn, error) {
		return b.dialer(10*time.Second).DialContext(ctx, "tcp", dialAddr)
	}

	// Track every underlying TCP conn this attempt dials so teardown can FORCE them shut. The h2
	// path is the leak that matters: x/net/http2 multiplexes the whole session over ONE conn and,
	// when we cancel the session's request on rotation, it only sends RST_STREAM — the TCP conn (its
	// fd + reader/writer goroutines) stays open. We set no IdleConnTimeout on the h2 transport and
	// never reuse it, and CloseIdleConnections races the async stream teardown (the stream count may
	// not be 0 yet at the instant we call it), so the retired conn can linger until the far side
	// happens to close it — or forever. Over hours of proactive rotation that accumulates fds and
	// goroutines until a new standby dial can no longer be made: rotation silently stops while the
	// already-open active conn keeps the tunnel up. Force-closing the raw conn on teardown is what
	// actually releases it. (Harmless for the http/1.1 packet-up path too — those conns are already
	// idle-reaped, and Close on an already-closed conn is a no-op error we ignore.)
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
	if b.wsTLS && b.xhTLS == nil {
		// Production TLS: uTLS with a Chrome fingerprint (see uEdgeHandshake), same as the ws
		// carrier — the xhttp handshake must not look like Go's crypto/tls either. packet-up rides
		// http/1.1 (force that ALPN); grpc/stream ride h2 (keep Chrome's [h2, http/1.1] so the edge
		// picks h2). We do the TLS ourselves via DialTLSContext so the transport never runs its own.
		var alpn []string
		if !h2 {
			alpn = []string{"http/1.1"}
		}
		dialTLS := func(ctx context.Context) (net.Conn, error) {
			c, err := rawDial(ctx)
			if err != nil {
				return nil, err
			}
			uc, err := uEdgeHandshake(b.fragWrap(c, host), host, ech, alpn) // split the ClientHello SNI when enabled
			if err != nil {
				c.Close()
				return nil, err
			}
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
			}
			rt, closeIdle = h2t, func() { h2t.CloseIdleConnections(); forceClose() }
		} else {
			tr := &http.Transport{
				DialTLSContext:      func(ctx context.Context, _, _ string) (net.Conn, error) { return dialTLS(ctx) },
				MaxIdleConns:        upIdleConns * 2,
				MaxIdleConnsPerHost: upIdleConns, // the GET holds one of these; the packet-up POSTs reuse the rest
				IdleConnTimeout:     90 * time.Second,
			}
			rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
		}
	} else {
		// No TLS (plain http), or a test that overrides the edge TLS wholesale (xhTLS). The
		// transport runs its own TLS (Go's) on a raw-dialed conn.
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, err := rawDial(ctx)
				if err != nil {
					return nil, err
				}
				if b.wsTLS {
					c = b.fragWrap(c, host)
				}
				return track(c), nil
			},
			ForceAttemptHTTP2:   h2,
			MaxIdleConns:        upIdleConns * 2,
			MaxIdleConnsPerHost: upIdleConns,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: handshakeTimeout,
		}
		if b.wsTLS {
			tr.TLSClientConfig = b.xhTLS
		}
		rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
	}

	scheme := "http"
	if b.wsTLS {
		scheme = "https"
	}
	sid := randSID()
	base := scheme + "://" + host + xhttpPath(path)
	hc := &http.Client{Transport: rt}
	ctx, cancel := context.WithCancel(context.Background())
	setHdr := func(r *http.Request) {
		r.Header.Set("User-Agent", chromeUA)
		r.Header.Set("Accept", "*/*")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Cache-Control", "no-store")
	}
	// Only two modes: grpc (one full-duplex request) and packet-up (default). Plain stream-one
	// (octet-stream) was removed because it stalled through CDNs that buffer the origin leg.
	var conn net.Conn
	var err error
	switch b.xhMode {
	case "grpc":
		conn, err = b.dialXHTTPGrpc(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr)
	default:
		conn, err = b.dialXHTTPPacket(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr)
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

// doWithHeaderTimeout runs hc.Do but bounds the wait for the response to BEGIN (headers received),
// not the streaming body that follows. The request context governs the whole session body, so it
// cannot also bound just this establishment step; without a separate bound, a CDN edge that
// completes TCP+TLS yet never starts streaming blocks the dial forever, stalling rotation and pin.
// On timeout the caller cancels the session ctx, which unblocks the parked goroutine (it returns
// context.Canceled into the buffered channel — no leak).
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
		return nil, fmt.Errorf("xhttp: response-header timeout (%s)", d)
	}
}

// --- gRPC framing (mode "grpc") ---------------------------------------------------------------
//
// gRPC rides the same single full-duplex request as stream-one, but presents as a real gRPC call
// so a CDN treats it as gRPC and connects to the ORIGIN over h2c — streaming the call both ways
// instead of buffering the request body (which is what stalls a plain stream over a CDN->origin
// HTTP/1.1 leg). On the wire: Content-Type application/grpc, and each frame is a gRPC length-
// prefixed message [0][uint32 len][msg] where msg is a minimal protobuf Hunk {bytes data = 1}
// carrying the payload — so a gRPC-aware proxy sees valid gRPC.

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
		msgLen := binary.BigEndian.Uint32(hdr[1:5])
		if msgLen > grpcMaxMsg {
			return 0, fmt.Errorf("xhttp/grpc: message too large (%d)", msgLen)
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

// dialXHTTPGrpc (grpc) is stream-one dressed as a gRPC call: one full-duplex POST with
// Content-Type application/grpc and gRPC message framing on both directions.
func (b *TCP) dialXHTTPGrpc(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request)) (net.Conn, error) {
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
	req.Header.Set("grpc-encoding", "identity")
	req.ContentLength = -1
	resp, err := doWithHeaderTimeout(hc, req, xhttpEstablishTimeout)
	if err != nil {
		cancel()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		pw.Close()
		return nil, fmt.Errorf("xhttp/grpc: got HTTP %d (want 200)", resp.StatusCode)
	}
	conn := &xhttpConn{
		r:  &grpcDeframingReader{r: resp.Body}, // Read <- deframed downstream
		w:  &grpcFramingWriter{w: pw},          // Write -> framed -> pipe -> request body (upstream)
		ra: strAddr(dialAddr), la: strAddr("xhttp-client"),
	}
	conn.closeFn = func() { cancel(); pw.Close(); resp.Body.Close(); closeIdle() }
	return conn, nil
}

// dialXHTTPPacket (packet-up) opens the long-lived downstream GET and starts the packet-up
// upstream sender for a fresh session, returning a net.Conn over the pair.
func (b *TCP) dialXHTTPPacket(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request)) (net.Conn, error) {
	greq, err := http.NewRequestWithContext(ctx, "GET", base+"?s="+sid, nil)
	if err != nil { // a malformed host/path would otherwise nil-deref inside doWithHeaderTimeout's goroutine
		cancel()
		return nil, err
	}
	setHdr(greq)
	gresp, err := doWithHeaderTimeout(hc, greq, xhttpEstablishTimeout)
	if err != nil {
		cancel()
		return nil, err
	}
	if gresp.StatusCode != http.StatusOK {
		gresp.Body.Close()
		cancel()
		return nil, fmt.Errorf("xhttp: down got HTTP %d (want 200)", gresp.StatusCode)
	}
	urlFor := func(seq uint64) string {
		return base + "?s=" + sid + "&seq=" + strconv.FormatUint(seq, 10)
	}
	conn := &xhttpConn{
		r:  gresp.Body,
		ra: strAddr(dialAddr), la: strAddr("xhttp-client"),
	}
	conn.closeFn = func() { cancel(); gresp.Body.Close(); closeIdle() }
	conn.up = newXhUp(ctx, hc, urlFor, setHdr, func() { conn.Close() })
	return conn, nil
}

// --- server ----------------------------------------------------------------------------------

type xhttpSession struct {
	upR    *io.PipeReader
	upW    *io.PipeWriter
	done   chan struct{}
	served chan struct{} // closed when a downstream GET binds and serve starts (the reap watchdog checks this)
	start  sync.Once
	end    sync.Once

	upMu    sync.Mutex        // orders packet-up POSTs by seq before writing to the upstream pipe
	nextSeq uint64            // next seq we expect to hand to upW
	pend    map[uint64][]byte // out-of-order chunks waiting for the gap to fill
}

// xhttpGetOrCreate returns the session for sid, creating it (with a fresh upstream pipe and a
// watchdog that reaps a session whose GET never arrives) on first sight.
func (b *TCP) xhttpGetOrCreate(sid string) *xhttpSession {
	b.xhMu.Lock()
	defer b.xhMu.Unlock()
	if s := b.xhSessions[sid]; s != nil {
		return s
	}
	pr, pw := io.Pipe()
	s := &xhttpSession{upR: pr, upW: pw, done: make(chan struct{}), served: make(chan struct{}), pend: map[uint64][]byte{}}
	b.xhSessions[sid] = s
	time.AfterFunc(handshakeTimeout, func() { s.reapIfUnserved(b, sid) })
	return s
}

// reapIfUnserved closes a session that never had a downstream GET bind (serve start) within the
// handshake window. It MUST spare a live session: the guard is s.served (closed when the GET starts
// serving), NOT s.done (closed only at session END) — checking s.done would reap every healthy
// packet-up session at handshakeTimeout.
func (s *xhttpSession) reapIfUnserved(b *TCP, sid string) {
	select {
	case <-s.served: // a GET bound and serve started -> live session, leave it
	case <-s.done: // already ended
	default:
		s.close(b, sid) // no downstream GET arrived in time -> reap the orphan
	}
}

// deliver feeds one packet-up chunk into the ordered upstream. Out-of-order chunks are buffered
// until the gap fills; already-delivered seqs are dropped. Writes happen under upMu so the byte
// stream stays correctly ordered even with several POSTs in flight.
func (s *xhttpSession) deliver(seq uint64, data []byte) {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	if seq < s.nextSeq {
		return // already delivered / duplicate
	}
	if len(s.pend) > 1024 { // runaway gap (a lost POST) — let the client fail + re-dial
		return
	}
	s.pend[seq] = data
	for {
		d, ok := s.pend[s.nextSeq]
		if !ok {
			break
		}
		delete(s.pend, s.nextSeq)
		s.nextSeq++
		if len(d) > 0 {
			if _, err := s.upW.Write(d); err != nil {
				return // session gone
			}
		}
	}
}

func (s *xhttpSession) close(b *TCP, sid string) {
	s.end.Do(func() {
		close(s.done)
		s.upW.Close()
		s.upR.Close()
		b.xhMu.Lock()
		delete(b.xhSessions, sid)
		b.xhMu.Unlock()
	})
}

// serveXHTTPGrpc handles a gRPC-framed full-duplex request: the single request IS the session, the
// body carries gRPC message framing and the response
// presents as gRPC (Content-Type application/grpc + a grpc-status trailer on clean close), so a
// CDN proxies it as a gRPC call (h2c to the origin, streamed, not buffered).
func (b *TCP) serveXHTTPGrpc(w http.ResponseWriter, r *http.Request) {
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
	conn := &xhttpConn{
		r:     &grpcDeframingReader{r: r.Body},
		w:     &grpcFramingWriter{w: w},
		flush: fl.Flush,
		ra:    strAddr(r.RemoteAddr), la: strAddr("xhttp-server"),
	}
	b.handleServerConn(conn) // the request lifetime IS the session; blocks until it ends
	conn.Close()
	w.Header().Set("grpc-status", "0") // OK (trailer)
}

// xhttpHandler routes a session's requests by shape. grpc is a single full-duplex POST with
// Content-Type application/grpc. packet-up uses a GET (downstream body, drives handleServerConn
// once) plus seq-tagged POSTs (?seq=N) fed into the upstream. The server auto-detects the style
// per request, so a grpc client and a packet client both work against one endpoint.
func (b *TCP) xhttpHandler(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	if len(sid) != 32 || strings.Trim(sid, "0123456789abcdef") != "" {
		http.Error(w, "Not Found", http.StatusNotFound) // a probe/scanner sees a plain 404
		return
	}
	// grpc: a single full-duplex POST presenting as a gRPC call (Content-Type application/grpc).
	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		b.serveXHTTPGrpc(w, r)
		return
	}
	s := b.xhttpGetOrCreate(sid)
	if r.Method == http.MethodPost {
		seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		data, rerr := io.ReadAll(io.LimitReader(r.Body, maxXhChunk))
		if rerr != nil {
			// A truncated body must NOT be delivered. Upstream is a length-prefixed AEAD stream, so a
			// short chunk at seq N shifts every following byte: readFrame consumes the next frame's
			// bytes as this one's payload and the desync cascades until the AEAD open fails — long
			// after the truncation, and charged to the edge as a data-plane fault. Answering 204
			// ("chunk accepted") made it worse: the client never learned and never re-dialled.
			// Dropping it is safe and self-correcting — deliver()'s gap guard stalls at nextSeq and
			// lets the client fail and re-dial, which restarts the stream cleanly.
			log.Printf("core/xhttp: truncated upstream chunk seq=%d (%d bytes read): %v — dropping so the client re-dials", seq, len(data), rerr)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		s.deliver(seq, data)
		w.WriteHeader(http.StatusNoContent) // 204: chunk accepted, session stays open
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // ask any nginx/CDN in front not to buffer
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	conn := &xhttpConn{
		r: s.upR, w: w, flush: fl.Flush,
		ra: strAddr(r.RemoteAddr), la: strAddr("xhttp-server"),
		closeFn: func() { s.close(b, sid) },
	}
	// Drive the authenticated core session once (the GET owns the downstream writer).
	s.start.Do(func() {
		close(s.served) // tell the reap watchdog a downstream GET bound in time — don't kill this live session at 10s
		go b.handleServerConn(conn)
	})
	<-s.done // hold the GET open (streaming downstream) until the session ends
}

// runXHTTPServer serves the xhttp endpoint until Close. A non-matching path/probe gets a plain
// 404 from the handler, so the port looks like an ordinary idle web endpoint.
func (b *TCP) runXHTTPServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.xhttpHandler)
	// Wrap in an h2c handler so a CDN can reach us over HTTP/2 cleartext. Cloudflare connects to
	// the origin with h2c when gRPC is enabled — that is the leg that STREAMS a full-duplex call
	// instead of buffering the request body (which stalls stream-one over a plain HTTP/1.1 origin).
	// h2c falls through to HTTP/1.1 for packet-up, so every mode shares this one plaintext listener.
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	b.httpSrv.Store(srv) // publish atomically so Close (another goroutine) sees it without a data race
	if err := srv.Serve(b.ln); err != nil && !b.closed.Load() {
		log.Printf("core/xhttp: server: %v", err)
	}
}
