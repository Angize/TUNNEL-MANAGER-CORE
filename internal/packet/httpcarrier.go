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
	"net/http/httptrace"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

const chromeAcceptEncoding = "gzip, deflate, br, zstd"

const grpcUA = "grpc-go/1.65.0"

const grpcAcceptEncoding = "gzip"

const maxPostBody = 1 << 20

const httpcHeaderWait = 3 * handshakeTimeout

type strAddr string

func (a strAddr) Network() string { return "http" }
func (a strAddr) String() string  { return string(a) }

type httpcConn struct {
	r  io.Reader
	aw asyncWriter

	wdl     atomic.Int64
	mu      sync.Mutex
	closed  bool
	closeFn func()
	idle    *time.Timer
	expired atomic.Bool
	ra, la  net.Addr
}

func (c *httpcConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && c.expired.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *httpcConn) Write(p []byte) (int, error) {
	return c.aw.write(p, c.wdl.Load())
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
		c.idle = time.AfterFunc(d, func() {
			c.expired.Store(true)
			c.Close()
		})
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

	if r.Method == http.MethodPost {
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

type seqChunk struct {
	seq  uint64
	data []byte
	own  *[]byte
}

const (
	MaxHTTPUpWorkers = 16
	MaxHTTPUpBatchKB = 512
	MaxHTTPUpRate    = 1000
)

var (
	maxUpBatch = 512 << 10

	upWorkers = 8

	upMinGap time.Duration
)

func SetHTTPUpstream(workers, batchKB, ratePerSec int) {
	if workers > 0 {
		upWorkers = workers
	}
	if batchKB > 0 {
		maxUpBatch = max(batchKB, 8) << 10
	}
	if ratePerSec > 0 {
		upMinGap = time.Second / time.Duration(ratePerSec)
	}
}

type httpcUp struct {
	hc     *http.Client
	ctx    context.Context
	urlFor func(seq uint64) string
	setHdr func(*http.Request)
	ch     chan *[]byte

	mu       sync.Mutex
	seq      uint64
	carry    *[]byte
	parts    []*[]byte
	lastSend time.Time

	minGap   time.Duration
	maxBatch int
	fail     func()
	once     sync.Once
}

func newHTTPCUp(ctx context.Context, hc *http.Client, urlFor func(uint64) string, setHdr func(*http.Request), fail func()) *httpcUp {
	u := &httpcUp{hc: hc, ctx: ctx, urlFor: urlFor, setHdr: setHdr, fail: fail,
		ch:     make(chan *[]byte, maxUpBatch/1400+2),
		minGap: upMinGap, maxBatch: maxUpBatch}
	for i := 0; i < upWorkers; i++ {
		go u.worker()
	}
	return u
}

func (u *httpcUp) write(p []byte, deadline int64) (int, error) {
	select {
	case <-u.ctx.Done():
		return 0, io.ErrClosedPipe
	default:
	}
	own := getChunk(len(p))
	copy(*own, p)
	select {
	case u.ch <- own:
		return len(p), nil
	default:
	}
	if deadline == 0 {
		select {
		case u.ch <- own:
			return len(p), nil
		case <-u.ctx.Done():
			putChunk(own)
			return 0, io.ErrClosedPipe
		}
	}
	t := time.NewTimer(time.Until(time.Unix(0, deadline)))
	defer t.Stop()
	select {
	case u.ch <- own:
		return len(p), nil
	case <-u.ctx.Done():
		putChunk(own)
		return 0, io.ErrClosedPipe
	case <-t.C:
		putChunk(own)
		return 0, os.ErrDeadlineExceeded
	}
}

func (u *httpcUp) next() (seqChunk, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	own := u.carry
	u.carry = nil
	if own == nil {
		select {
		case own = <-u.ch:
		case <-u.ctx.Done():
			return seqChunk{}, false
		}
	}
	if u.minGap > 0 && !u.lastSend.IsZero() {
		if d := u.minGap - time.Since(u.lastSend); d > 0 {
			t := time.NewTimer(d)
			select {
			case <-t.C:
			case <-u.ctx.Done():
				t.Stop()
				return seqChunk{}, false
			}
		}
	}
	total := len(*own)
	u.parts = append(u.parts[:0], own)
drain:
	for total < u.maxBatch {
		select {
		case more := <-u.ch:
			if total+len(*more) > u.maxBatch {
				u.carry = more
				break drain
			}
			u.parts = append(u.parts, more)
			total += len(*more)
		default:
			break drain
		}
	}
	if len(u.parts) > 1 {
		own = getChunk(total)
		buf := (*own)[:0]
		for _, p := range u.parts {
			buf = append(buf, *p...)
			putChunk(p)
		}
	}
	clear(u.parts)
	u.lastSend = time.Now()
	sc := seqChunk{u.seq, *own, own}
	u.seq++
	return sc, true
}

func (u *httpcUp) worker() {
	for {
		sc, ok := u.next()
		if !ok {
			return
		}
		if err := u.post(sc); err != nil {
			u.once.Do(u.fail)
			return
		}
	}
}

func (u *httpcUp) post(sc seqChunk) error {
	ctx, cancel := context.WithTimeout(u.ctx, writeTimeout)
	defer cancel()
	var writing atomic.Int32
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn:      func(httptrace.GotConnInfo) { writing.Add(1) },
		WroteRequest: func(httptrace.WroteRequestInfo) { writing.Add(-1) },
	})
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
	if writing.Load() == 0 {
		putChunk(sc.own)
	}
	return nil
}

func (b *TCP) establishHTTPC() (net.Conn, string, string, error) {
	dialAddr, host, ech, err := b.edgeTarget("httpc")
	if err != nil {
		return nil, "", "", err
	}
	conn, err := b.dialHTTPCOnce(dialAddr, host, ech)

	if err != nil && b.wsTLS && len(ech) > 0 {
		if retry, ok := echRetry(err); ok {
			ech = retry
			log.Printf("core/http: ECH self-heal for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			conn, err = b.dialHTTPCOnce(dialAddr, host, ech)
			if err == nil {
				b.noteECHSelfHeal(host, ech)
			}
		}
	}

	if err != nil {
		return nil, dialAddr, "", err
	}
	return conn, dialAddr, activeLabel(dialAddr, host), nil
}

func (b *TCP) dialHTTPCOnce(dialAddr, host string, ech []byte) (net.Conn, error) {
	h2 := b.httpcMode == "grpc" && b.wsTLS

	rawDial := func(ctx context.Context) (net.Conn, error) {
		return dialFromBand(ctx, func() *net.Dialer { return b.dialer(connectTimeout) }, dialAddr)
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
	if b.wsTLS {
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

			uc, err := uEdgeHandshake(b.fragWrap(c, host, ech), host, ech, b.wsRoots, alpn, h2, handshakeTimeout)
			if err != nil {
				c.Close()
				return nil, stageErr{stageTLS, err}
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
				MaxIdleConns:        upWorkers * 4,
				MaxIdleConnsPerHost: upWorkers * 2,
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
				return track(c), nil
			},
			MaxIdleConns:        upWorkers * 4,
			MaxIdleConnsPerHost: upWorkers * 2,
			IdleConnTimeout:     90 * time.Second,
		}
		rt, closeIdle = tr, func() { tr.CloseIdleConnections(); forceClose() }
	}

	scheme := "http"
	if b.wsTLS {
		scheme = "https"
	}
	sid := randSID()
	base := scheme + "://" + host + b.wsPath
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
		conn, err = b.dialHTTPCGrpc(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr)
	default:
		conn, err = b.dialHTTPCPost(hc, closeIdle, ctx, cancel, base, sid, dialAddr, setHdr)
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

func grpcAppendFrame(dst, p []byte) []byte {
	var hunk [1 + binary.MaxVarintLen64]byte
	hunk[0] = 0x0a
	h := 1 + binary.PutUvarint(hunk[1:], uint64(len(p)))
	dst = append(dst, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(dst[len(dst)-4:], uint32(h+len(p)))
	dst = append(dst, hunk[:h]...)
	return append(dst, p...)
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
	own := getChunk(5 + 1 + binary.MaxVarintLen64 + len(p))
	if _, err := g.w.Write(grpcAppendFrame((*own)[:0], p)); err != nil {
		return 0, err
	}
	putChunk(own)
	return len(p), nil
}

type grpcDeframingReader struct {
	r   io.Reader
	buf []byte
	own *[]byte
}

func (g *grpcDeframingReader) Read(p []byte) (int, error) {
	for len(g.buf) == 0 {
		putChunk(g.own)
		g.own = nil
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
		own := getChunk(int(msgLen))
		if _, err := io.ReadFull(g.r, *own); err != nil {
			putChunk(own)
			return 0, err
		}
		g.own = own
		g.buf = grpcUnhunk(*own)
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	if len(g.buf) == 0 {
		putChunk(g.own)
		g.own = nil
	}
	return n, nil
}

func (g *grpcDeframingReader) Close() error {
	if c, ok := g.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (b *TCP) openGrpcStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request)) (*http.Response, *io.PipeWriter, error) {
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
	resp, err := doWithHeaderTimeout(hc, req, httpcHeaderWait)
	if err != nil {
		pw.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		if resp.StatusCode == http.StatusForbidden {
			return nil, nil, edgeHTTPErr{errors.New("http/grpc: got HTTP 403 — enable gRPC on the zone (Cloudflare: Network -> gRPC) " +
				"or use ws / http; the application/grpc content-type alone triggers it")}
		}
		return nil, nil, edgeHTTPErr{fmt.Errorf("http/grpc: got HTTP %d (want 200)", resp.StatusCode)}
	}
	return resp, pw, nil
}

func (b *TCP) runGrpcStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), tx *stripeTx, q *reseq, fail func(), first *http.Response, firstPW *io.PipeWriter) {
	resp, pw := first, firstPW
	for {
		if resp == nil {
			var err error
			if resp, pw, err = b.openGrpcStream(hc, ctx, base, sid, i, setHdr); err != nil {
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

func newHTTPCClientConn(dialAddr string, cancel, closeIdle func()) (*httpcConn, *io.PipeWriter, func()) {
	pr, pw := io.Pipe()
	conn := &httpcConn{r: pr, ra: strAddr(dialAddr), la: strAddr("http-client")}
	conn.closeFn = func() { cancel(); pw.Close(); closeIdle() }
	return conn, pw, func() { conn.Close() }
}

func (b *TCP) dialHTTPCGrpc(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request)) (net.Conn, error) {
	first, firstPW, err := b.openGrpcStream(hc, ctx, base, sid, 0, setHdr)
	if err != nil {
		cancel()
		return nil, err
	}
	conn, pw, fail := newHTTPCClientConn(dialAddr, cancel, closeIdle)
	tx := newStripeTx(ctx.Done())
	conn.aw = tx
	q := newReseq(pw, maxStripePend(1))
	go b.runGrpcStream(hc, ctx, base, sid, 0, setHdr, tx, q, fail, first, firstPW)
	for i := 1; i < carrierStreams; i++ {
		go b.runGrpcStream(hc, ctx, base, sid, i, setHdr, tx, q, fail, nil, nil)
	}
	return conn, nil
}

func (b *TCP) openDownStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request)) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"?s="+sid+"&d="+strconv.Itoa(i), nil)
	if err != nil {
		return nil, err
	}
	setHdr(req)
	resp, err := doWithHeaderTimeout(hc, req, httpcHeaderWait)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, edgeHTTPErr{fmt.Errorf("httpc: down got HTTP %d (want 200)", resp.StatusCode)}
	}
	if enc := resp.Header.Get("Content-Encoding"); downstreamUnusable(enc) {
		resp.Body.Close()
		return nil, edgeHTTPErr{fmt.Errorf("httpc: down came back %s-encoded — this edge compresses the downstream, "+
			"which the carrier cannot decode; turn compression off for this path at the CDN", enc)}
	}
	return resp, nil
}

func (b *TCP) runDownStream(hc *http.Client, ctx context.Context, base, sid string, i int, setHdr func(*http.Request), q *reseq, fail func()) {
	for {
		if resp, err := b.openDownStream(hc, ctx, base, sid, i, setHdr); err == nil {
			readStripe(resp.Body, q, fail)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(stripeRetry):
		}
	}
}

func (b *TCP) dialHTTPCPost(hc *http.Client, closeIdle func(), ctx context.Context, cancel func(), base, sid, dialAddr string, setHdr func(*http.Request)) (net.Conn, error) {
	first, err := b.openDownStream(hc, ctx, base, sid, 0, setHdr)
	if err != nil {
		cancel()
		return nil, err
	}
	urlFor := func(seq uint64) string {
		return base + "?s=" + sid + "&seq=" + strconv.FormatUint(seq, 10)
	}
	conn, pw, fail := newHTTPCClientConn(dialAddr, cancel, closeIdle)
	q := newReseq(pw, maxStripePend(carrierStreams))
	go func() {
		readStripe(first.Body, q, fail)
		b.runDownStream(hc, ctx, base, sid, 0, setHdr, q, fail)
	}()
	for i := 1; i < carrierStreams; i++ {
		go b.runDownStream(hc, ctx, base, sid, i, setHdr, q, fail)
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

func (s *httpcSession) startConn(b *TCP, sid, remote string) {
	s.start.Do(func() {
		go b.handleServerConn(&httpcConn{
			r:       s.upR,
			aw:      s.down,
			ra:      strAddr(remote),
			la:      strAddr("http-server"),
			closeFn: func() { s.close(b, sid) },
		})
	})
}

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
	s.startConn(b, sid, r.RemoteAddr)
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

func readPostBody(r *http.Request, pool bool) ([]byte, *[]byte, error) {
	cl := r.ContentLength
	if cl < 0 || cl >= maxPostBody {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxPostBody))
		return data, nil, err
	}
	var own *[]byte
	var buf []byte
	if pool {
		own = getChunk(int(cl))
		buf = *own
	} else {
		buf = make([]byte, cl)
	}
	m := 0
	var tail [1]byte
	for {
		dst := buf[m:]
		if m == len(buf) {
			dst = tail[:]
		}
		k, err := r.Body.Read(dst)
		if m == len(buf) && k > 0 {
			return buf, own, io.ErrUnexpectedEOF
		}
		m += k
		if err == io.EOF {
			return buf[:m], own, nil
		}
		if err != nil {
			return buf[:m], own, err
		}
	}
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
		data, own, rerr := readPostBody(r, s.up.due(seq))
		if rerr != nil {
			log.Printf("core/http: truncated upstream chunk seq=%d (%d bytes read): %v — dropping so the client re-dials", seq, len(data), rerr)
			putChunk(own)
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if !s.up.deliver(seq, data, own) {
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

	s.startConn(b, sid, r.RemoteAddr)
	s.down.serve(r.Context(), w, fl.Flush, http.NewResponseController(w).SetWriteDeadline)
}

func (b *TCP) runHTTPCServer() {
	mux := http.NewServeMux()
	mux.HandleFunc(b.wsPath, b.httpcHandler)

	h2s := &http2.Server{}
	if n := wantTCPBuf(); n > 0 {
		h2s.MaxUploadBufferPerConnection = int32(n)
		h2s.MaxUploadBufferPerStream = int32(n)
	}
	srv := &http.Server{Handler: h2c.NewHandler(mux, h2s)}
	b.httpSrv.Store(srv)
	if err := srv.Serve(b.lns[0]); err != nil && !b.closed.Load() {
		log.Printf("core/http: server: %v", err)
	}
}
