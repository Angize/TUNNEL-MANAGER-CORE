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

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

const chromeAcceptEncoding = "gzip, deflate, br, zstd"

const grpcUA = "grpc-go/1.65.0"

const grpcAcceptEncoding = "gzip"

const maxPostBody = 1 << 20

func httpcHeaderWait(budget time.Duration) time.Duration { return 3 * budget }

type strAddr string

func (a strAddr) Network() string { return "http" }
func (a strAddr) String() string  { return string(a) }

type httpcConn struct {
	r     io.Reader
	w     io.Writer
	flush func()
	aw    asyncWriter

	wmu     sync.Mutex
	wdl     atomic.Int64
	setWD   func(time.Time) error
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	ra, la  net.Addr
}

func (c *httpcConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *httpcConn) armWrite() func() {
	dl := c.wdl.Load()
	if dl == 0 {
		return func() {}
	}
	t := time.AfterFunc(time.Until(time.Unix(0, dl)), func() {
		if c.setWD != nil {
			_ = c.setWD(time.Unix(0, 1))
			return
		}
		c.Close()
	})
	return func() { t.Stop() }
}

func (c *httpcConn) Write(p []byte) (int, error) {
	if c.aw != nil {
		return c.aw.write(p, c.wdl.Load())
	}

	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {

		return 0, net.ErrClosed
	}
	if dl := c.wdl.Load(); dl != 0 && time.Now().UnixNano() > dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()

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

var chromeClientHints = [][2]string{
	{"sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`},
	{"sec-ch-ua-mobile", "?0"},
	{"sec-ch-ua-platform", `"Windows"`},
	{"Sec-Fetch-Dest", "empty"},
	{"Sec-Fetch-Mode", "cors"},
	{"Sec-Fetch-Site", "same-origin"},
}

func browserHeaders(r *http.Request) {
	r.Header.Set("User-Agent", chromeUA)
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Encoding", chromeAcceptEncoding)
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Cache-Control", "no-store")
	for _, h := range chromeClientHints {
		r.Header.Set(h[0], h[1])
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL != nil && r.URL.Host != "" {
		r.Header.Set("Origin", "https://"+r.URL.Host)
	}
}

func downstreamUnusable(enc string) bool {
	e := strings.ToLower(strings.TrimSpace(enc))
	return e != "" && e != "identity"
}

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

type seqChunk struct {
	seq  uint64
	data []byte
}

var (
	maxUpBatch = 128 << 10

	upWorkers = 8

	upChanCap = maxUpBatch/1400 + 2

	upIdleConns = upWorkers * 2

	upMinGap time.Duration
)

const upWorkCap = 1

func SetHTTPUpstream(workers, batchKB, ratePerSec int) {
	if workers > 0 {
		upWorkers = tclamp(workers, 1, 16)
		upIdleConns = upWorkers * 2
	}
	if batchKB > 0 {

		maxUpBatch = tclamp(batchKB, 8, 512) << 10
		upChanCap = maxUpBatch/1400 + 2
	}
	if ratePerSec > 0 {
		upMinGap = time.Second / time.Duration(tclamp(ratePerSec, 1, 1000))
	}
}

type httpcUp struct {
	hc     *http.Client
	ctx    context.Context
	urlFor func(seq uint64) string
	setHdr func(*http.Request)
	seq    uint64
	ch     chan []byte
	work   chan seqChunk

	minGap   time.Duration
	maxBatch int
	postTO   time.Duration
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
					carry = more
					break drain
				}
				buf = append(buf, more...)
			case <-u.ctx.Done():
				return
			default:
				break drain
			}
		}
		if u.minGap > 0 {
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
				u.once.Do(u.fail)
				return
			}
		}
	}
}

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
	b.noteAttempt(host, dialAddr)
	return dialAddr, host, ech, path, nil
}

func (b *TCP) establishHTTPC() (net.Conn, string, string, error) {
	dialAddr, host, ech, path, err := b.httpcEdge()
	if err != nil {
		return nil, "", "", err
	}
	conn, err := b.dialHTTPCOnce(dialAddr, host, ech, path, handshakeTimeout)

	if err != nil && b.wsTLS && len(ech) > 0 {
		var echErr *utls.ECHRejectionError
		if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList
			log.Printf("core/http: ECH self-heal for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			conn, err = b.dialHTTPCOnce(dialAddr, host, ech, path, handshakeTimeout)
			if err == nil {
				b.noteECHSelfHeal(host, ech)
			}
		}
	}

	if err != nil {
		b.pinFailedOn(dialAddr, host)
		return nil, dialAddr, "", err
	}
	return conn, dialAddr, activeLabel(dialAddr, host), nil
}

func (b *TCP) dialHTTPCOnce(dialAddr, host string, ech []byte, path string, budget time.Duration) (net.Conn, error) {
	single := b.httpcMode == "grpc"
	h2 := single && b.wsTLS

	rawDial := func(ctx context.Context) (net.Conn, error) {
		d := budget
		if d > connectTimeout {
			d = connectTimeout
		}
		return b.dialer(d).DialContext(ctx, "tcp", dialAddr)
	}

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

			uc, err := uEdgeHandshake(b.fragWrap(c, host, ech), host, ech, alpn, h2, budget)
			if err != nil {
				c.Close()
				return nil, err
			}
			_ = c.SetDeadline(time.Time{})
			track(c)
			return uc, nil
		}
		if h2 {

			h2t := &http2.Transport{
				DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return dialTLS(ctx)
				},

				DisableCompression: true,
			}
			rt, closeIdle = h2t, func() { h2t.CloseIdleConnections(); forceClose() }
		} else {
			tr := &http.Transport{
				DialTLSContext:      func(ctx context.Context, _, _ string) (net.Conn, error) { return dialTLS(ctx) },
				MaxIdleConns:        upIdleConns * 2,
				MaxIdleConnsPerHost: upIdleConns,
				IdleConnTimeout:     90 * time.Second,
			}
			rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
		}
	} else {

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
			DisableCompression:  h2,
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

	var conn net.Conn
	var err error
	switch b.httpcMode {
	case "grpc":
		conn, err = b.dialHTTPCGrpc(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr, budget)
	default:
		conn, err = b.dialHTTPCPost(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr, budget)
	}
	if err != nil {

		closeIdle()
	}
	return conn, err
}

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

const grpcMaxMsg = 1 << 20

func grpcFrame(p []byte) []byte {
	hunk := make([]byte, 0, 1+binary.MaxVarintLen64)
	hunk = append(hunk, 0x0a)
	hunk = binary.AppendUvarint(hunk, uint64(len(p)))
	msgLen := len(hunk) + len(p)
	buf := make([]byte, 5+msgLen)
	buf[0] = 0
	binary.BigEndian.PutUint32(buf[1:5], uint32(msgLen))
	n := copy(buf[5:], hunk)
	copy(buf[5+n:], p)
	return buf
}

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

type grpcFramingWriter struct{ w io.Writer }

func (g *grpcFramingWriter) Write(p []byte) (int, error) {
	if _, err := g.w.Write(grpcFrame(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

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

func (g *grpcDeframingReader) Close() error {
	if c, ok := g.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// One gRPC call: a request whose body the client keeps writing and a response it keeps reading. The
// index is in the URL so the edge sees distinct calls rather than n identical ones.
func (b *TCP) openGrpcStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), budget time.Duration, dialAddr string) (*http.Response, *io.PipeWriter, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", base+"?s="+sid+"&d="+strconv.Itoa(i), pr)
	if err != nil {
		pw.Close()
		return nil, nil, err
	}
	setHdr(req)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.ContentLength = -1
	resp, err := doWithHeaderTimeout(hc, req, httpcHeaderWait(budget))
	if err != nil {
		pw.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		if resp.StatusCode == http.StatusForbidden {
			return nil, nil, fmt.Errorf("http/grpc: the CDN edge refused the gRPC request with HTTP 403 — "+
				"measured on a live edge, this is the Content-Type: application/grpc header alone, and "+
				"Cloudflare needs gRPC enabled on the zone (Network -> gRPC) before it will proxy it. "+
				"Turn it on for %s, or use the plain ws / http carrier shape instead", dialAddr)
		}
		return nil, nil, fmt.Errorf("http/grpc: got HTTP %d (want 200)", resp.StatusCode)
	}
	return resp, pw, nil
}

// One gRPC stream, reopened for as long as the carrier lives. Its two halves are tied together: when
// the reader ends it closes the request body, so the writer's next record fails and goes back on the
// queue for another stream rather than into a call nobody is answering.
func (b *TCP) runGrpcStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), budget time.Duration, dialAddr string, tx *stripeTx, q *reseq, fail func(), first *http.Response, firstPW *io.PipeWriter) {
	resp, pw := first, firstPW
	for {
		if resp == nil {
			var err error
			if resp, pw, err = b.openGrpcStream(hc, ctx, base, sid, i, setHdr, budget, dialAddr); err != nil {
				resp = nil
				select {
				case <-ctx.Done():
					return
				case <-time.After(stripeRetry):
				}
				continue
			}
		}
		q.attach(1)
		read := make(chan struct{})
		go func(resp *http.Response, pw *io.PipeWriter) {
			readStripe(&grpcDeframingReader{r: resp.Body}, q, fail)
			pw.Close()
			close(read)
		}(resp, pw)
		tx.serve(ctx, &grpcFramingWriter{w: pw}, func() {}, nil)
		pw.Close()
		resp.Body.Close()
		<-read
		if q.attach(-1) == 0 {
			fail()
			return
		}
		resp, pw = nil, nil
		select {
		case <-ctx.Done():
			return
		case <-time.After(stripeRetry):
		}
	}
}

func (b *TCP) dialHTTPCGrpc(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request), budget time.Duration) (net.Conn, error) {
	first, firstPW, err := b.openGrpcStream(hc, ctx, base, sid, 0, setHdr, budget, dialAddr)
	if err != nil {
		cancel()
		return nil, err
	}
	pr, pw := io.Pipe()
	tx := newStripeTx(ctx.Done())
	conn := &httpcConn{
		r: pr, aw: tx,
		ra: strAddr(dialAddr), la: strAddr("http-client"),
	}
	conn.closeFn = func() { cancel(); pw.Close(); closeIdle() }
	fail := func() { conn.Close() }
	q := newReseq(pw, maxStripePend(1))
	go b.runGrpcStream(hc, ctx, base, sid, 0, setHdr, budget, dialAddr, tx, q, fail, first, firstPW)
	for i := 1; i < carrierStreams; i++ {
		go b.runGrpcStream(hc, ctx, base, sid, i, setHdr, budget, dialAddr, tx, q, fail, nil, nil)
	}
	return conn, nil
}

func (b *TCP) openDownStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), budget time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"?s="+sid+"&d="+strconv.Itoa(i), nil)
	if err != nil {
		return nil, err
	}
	setHdr(req)
	resp, err := doWithHeaderTimeout(hc, req, httpcHeaderWait(budget))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("httpc: down got HTTP %d (want 200)", resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); downstreamUnusable(enc) {
		resp.Body.Close()
		return nil, fmt.Errorf("httpc: down came back %s-encoded — this edge compresses the downstream, "+
			"which the carrier cannot decode; turn compression off for this path at the CDN", enc)
	}
	return resp, nil
}

// One download stream, reopened for as long as the carrier lives. Neither failing to open nor dying
// once open ends the tunnel: the server puts back whatever a dead stream did not deliver, and the
// carrier runs on whichever streams are up. A path that drops a burst of SYNs will not bring them all
// up at once, and on a censored one they come and go for the life of the tunnel.
func (b *TCP) runDownStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), budget time.Duration, q *reseq, fail func()) {
	for {
		if resp, err := b.openDownStream(hc, ctx, base, sid, i, setHdr, budget); err == nil {
			readStripe(resp.Body, q, fail)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(stripeRetry):
		}
	}
}

func (b *TCP) dialHTTPCPost(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request), budget time.Duration) (net.Conn, error) {
	first, err := b.openDownStream(hc, ctx, base, sid, 0, setHdr, budget)
	if err != nil {
		cancel()
		return nil, err
	}
	urlFor := func(seq uint64) string {
		return base + "?s=" + sid + "&seq=" + strconv.FormatUint(seq, 10)
	}
	pr, pw := io.Pipe()
	conn := &httpcConn{
		r:  pr,
		ra: strAddr(dialAddr), la: strAddr("http-client"),
	}
	conn.closeFn = func() { cancel(); pw.Close(); closeIdle() }
	fail := func() { conn.Close() }
	q := newReseq(pw, maxStripePend(carrierStreams))
	go func() {
		readStripe(first.Body, q, fail)
		b.runDownStream(hc, ctx, base, sid, 0, setHdr, budget, q, fail)
	}()
	for i := 1; i < carrierStreams; i++ {
		go b.runDownStream(hc, ctx, base, sid, i, setHdr, budget, q, fail)
	}
	conn.aw = newHTTPCUp(ctx, hc, urlFor, setHdr, fail)
	return conn, nil
}

type httpcSession struct {
	upR   *io.PipeReader
	upW   *io.PipeWriter
	up    *reseq
	down  *stripeTx
	done  chan struct{}
	start sync.Once
	end   sync.Once
}

func (b *TCP) httpcGetOrCreate(sid string) *httpcSession {
	b.httpcMu.Lock()
	defer b.httpcMu.Unlock()
	if s := b.httpcSessions[sid]; s != nil {
		return s
	}
	s := newHTTPCSession()
	b.httpcSessions[sid] = s
	return s
}

func newHTTPCSession() *httpcSession {
	pr, pw := io.Pipe()
	done := make(chan struct{})
	return &httpcSession{upR: pr, upW: pw, up: newReseq(pw, maxPendBytes()), down: newStripeTx(done), done: done}
}

func (b *TCP) httpcLookup(sid string) *httpcSession {
	b.httpcMu.Lock()
	defer b.httpcMu.Unlock()
	return b.httpcSessions[sid]
}

func maxPendBytes() int {
	if n := 2 * upWorkers * maxUpBatch; n > 4<<20 {
		return n
	}
	return 4 << 20
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

// The conn for a carrier that writes straight into one response. The parallel download does not use
// it: there its writes go to the session queue, and the deadline is set per stream in writeRecord.
func newHTTPCServerConn(w http.ResponseWriter, rd io.Reader, wr io.Writer, flush func(), remote string, closeFn func()) *httpcConn {
	return &httpcConn{
		r: rd, w: wr, flush: flush,
		setWD:   http.NewResponseController(w).SetWriteDeadline,
		ra:      strAddr(remote),
		la:      strAddr("http-server"),
		closeFn: closeFn,
	}
}

// One attached gRPC stream of a session. Same shape as the http carrier's download half, in both
// directions at once: records in, records out, and the session is what ties the streams together.
func (b *TCP) serveHTTPCGrpc(w http.ResponseWriter, r *http.Request, sid string) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("grpc-encoding", "identity")
	w.Header().Set("Trailer", "grpc-status")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	s := b.httpcGetOrCreate(sid)
	s.start.Do(func() {
		go b.handleServerConn(&httpcConn{
			r:       s.upR,
			aw:      s.down,
			ra:      strAddr(r.RemoteAddr),
			la:      strAddr("http-server"),
			closeFn: func() { s.close(b, sid) },
		})
	})
	s.up.attach(1)
	defer func() {
		if s.up.attach(-1) == 0 {
			s.close(b, sid)
		}
	}()
	read := make(chan struct{})
	go func() {
		readStripe(&grpcDeframingReader{r: r.Body}, s.up, func() { s.close(b, sid) })
		close(read)
	}()
	s.down.serve(r.Context(), &grpcFramingWriter{w: w}, fl.Flush, http.NewResponseController(w).SetWriteDeadline)
	<-read
	w.Header().Set("grpc-status", "0")
}

func (b *TCP) httpcHandler(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("s")
	if len(sid) != 32 || strings.Trim(sid, "0123456789abcdef") != "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		b.serveHTTPCGrpc(w, r, sid)
		return
	}
	if r.Method == http.MethodPost {

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

			log.Printf("core/http: truncated upstream chunk seq=%d (%d bytes read): %v — dropping so the client re-dials", seq, len(data), rerr)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if !s.up.deliver(seq, data) {

			http.Error(w, "", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
	s := b.httpcGetOrCreate(sid)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	// The carrier belongs to the session, not to this request: the first GET starts it and every GET
	// after it is one more stream the same queue can write down.
	s.start.Do(func() {
		go b.handleServerConn(&httpcConn{
			r:       s.upR,
			aw:      s.down,
			ra:      strAddr(r.RemoteAddr),
			la:      strAddr("http-server"),
			closeFn: func() { s.close(b, sid) },
		})
	})
	s.down.serve(r.Context(), w, fl.Flush, http.NewResponseController(w).SetWriteDeadline)
}

func (b *TCP) runHTTPCServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", b.httpcHandler)

	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	b.httpSrv.Store(srv)
	if err := srv.Serve(b.ln); err != nil && !b.closed.Load() {
		log.Printf("core/http: server: %v", err)
	}
}
