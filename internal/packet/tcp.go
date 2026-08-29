package packet

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/cryptobyte"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tlscover"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	maxFrame = 65535

	readBufSize = 4096

	tunBatchFrames = 32

	handshakeTimeout = 10 * time.Second

	connectTimeout = 4 * time.Second

	writeTimeout = 30 * time.Second

	maxPreAuthConns = 128

	maxAuthConns = 3
)

var (
	errDesync = errors.New("core/tcp: stream desync")

	errFrameTooBig = errors.New("core/tcp: frame exceeds max size")
)

type connFramer struct {
	conn   net.Conn
	r      *bufio.Reader
	mu     sync.Mutex
	sealer Sealer
	obfs   bool
	psk    string

	writeKS  *chacha20.Cipher
	readKS   *chacha20.Cipher
	saltSent bool

	saltPend []byte
	wbuf     []byte

	rp replayGuard

	rxAt atomic.Int64
}

func (cf *connFramer) sendSalt() error {
	if cf.saltSent {
		return nil
	}
	salt := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	ws, err := newObfsStream(cf.psk, salt)
	if err != nil {
		return err
	}
	cf.mu.Lock()
	cf.writeKS = ws
	cf.saltPend = salt
	cf.saltSent = true
	cf.mu.Unlock()
	return nil
}

func (cf *connFramer) flushSalt() error {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if len(cf.saltPend) == 0 {
		return nil
	}
	salt := cf.saltPend
	cf.saltPend = nil
	cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := cf.conn.Write(salt)
	return err
}

func (cf *connFramer) ensureReadKS() error {
	if cf.readKS != nil {
		return nil
	}
	peer := make([]byte, obfsSaltLen)
	if _, err := io.ReadFull(cf.r, peer); err != nil {
		return err
	}
	rs, err := newObfsStream(cf.psk, peer)
	if err != nil {
		return err
	}
	cf.readKS = rs
	return nil
}

func (cf *connFramer) frame(typ byte, payload []byte) ([]byte, error) {
	if cf.obfs {
		sealed, err := obfsSeal(cf.sealer, typ, payload, padMaxFor(typ))
		if err != nil {
			return nil, err
		}
		if len(sealed) > maxFrame {
			return nil, errFrameTooBig
		}
		out := make([]byte, 2+len(sealed))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(sealed)))
		copy(out[2:], sealed)
		return out, nil
	}
	sealed := payload
	if cf.sealer != nil {
		s, err := cf.sealer.Seal(payload, []byte{typ})
		if err != nil {
			return nil, err
		}
		sealed = s
	}
	n := 2 + len(sealed)
	if n > maxFrame {
		return nil, errFrameTooBig
	}
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out[0:2], uint16(n))
	out[2] = magic
	out[3] = typ
	copy(out[4:], sealed)
	return out, nil
}

func (cf *connFramer) writeAll(frames [][]byte) error {
	if len(frames) == 0 {
		return nil
	}
	cf.mu.Lock()
	defer cf.mu.Unlock()
	out := cf.wbuf[:0]
	if len(cf.saltPend) > 0 {
		out = append(out, cf.saltPend...)
		cf.saltPend = nil
	}
	var lb [2]byte
	for _, f := range frames {
		if cf.obfs {
			copy(lb[:], f[0:2])
			cf.writeKS.XORKeyStream(f[0:2], lb[:])
		}
		out = append(out, f...)
	}
	cf.wbuf = out
	cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := cf.conn.Write(out)
	return err
}

func (cf *connFramer) writeFrame(typ byte, payload []byte) error {
	f, err := cf.frame(typ, payload)
	if err != nil {
		return err
	}
	return cf.writeAll([][]byte{f})
}

func (cf *connFramer) readFrame() (typ byte, session uint64, seq uint64, payload []byte, err error) {
	if cf.obfs {
		if err := cf.ensureReadKS(); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(cf.r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	if cf.obfs {
		var lb [2]byte
		cf.readKS.XORKeyStream(lb[:], hdr[:])
		n := int(binary.BigEndian.Uint16(lb[:]))

		if n < 1 {
			return 0, 0, 0, nil, errDesync
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(cf.r, buf); err != nil {
			return 0, 0, 0, nil, err
		}
		return obfsOpen(cf.sealer, buf)
	}

	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 2 {
		return 0, 0, 0, nil, errDesync
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(cf.r, buf); err != nil {
		return 0, 0, 0, nil, err
	}
	if buf[0] != magic {
		return 0, 0, 0, nil, errDesync
	}
	typ = buf[1]
	if cf.sealer != nil {
		session, seq, payload, err = cf.sealer.Open(buf[2:n], []byte{typ})
		if err != nil {
			return 0, 0, 0, nil, err
		}
		return typ, session, seq, payload, nil
	}
	if typ == typeData {
		return typ, 0, 0, buf[2:n], nil
	}
	return typ, 0, 0, nil, nil
}

type TCP struct {
	dev      *tun.Device
	tw       *tunWriters
	twOnce   sync.Once
	cryptoOn bool
	cipher   string
	obfs     bool
	psk      string
	idle     time.Duration
	ping     time.Duration

	cover     bool
	coverSNI  string
	coverHint sync.Once
	coverSrv  *tlscover.Server

	ws     bool
	wsHost string
	wsPath string
	wsTLS  bool

	echMu sync.Mutex
	wsECH []byte

	pool   *wsPool
	rotate time.Duration
	st     *coreStatus
	stTag  string
	lastRx atomic.Int64

	lastRxData atomic.Int64

	pp *PeerPool

	sp *PeerPool

	sniSplit bool
	splitPos int
	sniMode  string
	splitTTL int

	manualSwitch atomic.Bool

	lastErr atomic.Value

	httpc         bool
	httpcMode     string
	httpcTLS      *tls.Config
	httpSrv       atomic.Pointer[http.Server]
	httpcMu       sync.Mutex
	httpcSessions map[string]*httpcSession

	isClient bool
	addr     string
	bindIP   string

	rc     rotationController
	rolled atomic.Bool

	srcWarned sync.Map

	lastSrc atomic.Pointer[string]

	dsOn       bool
	dsTTL      int
	dsCount    int
	dsMode     string
	dsFailOnce sync.Once
	dsSend     desyncSend

	dsWatch func(net.Conn)

	ln      net.Listener
	lns     []net.Listener
	cur     atomic.Pointer[connFramer]
	curConn atomic.Pointer[net.Conn]

	liveSNI  atomic.Pointer[string]
	livePair atomic.Pointer[pairNow]
	tryPair  atomic.Pointer[pairNow]

	attempted atomic.Bool
	closed    atomic.Bool
	closeCh   chan struct{}
	preAuth   chan struct{}

	authMu    sync.Mutex
	authConns []*connFramer
}

func (b *TCP) SetSourceIP(ip string) { b.bindIP = ip }

func (b *TCP) SetPeerPool(pp *PeerPool) {
	if b.isClient && !b.ws {
		b.pp = pp
		joinStatus(b.st, pp, "dst")
		b.rc.bind(pp, b.sp)
		b.publishPair()
	}
}

func (b *TCP) livePairNow() (low, high string) {
	if lp := b.livePair.Load(); lp != nil && b.cur.Load() != nil {
		return lp.low, lp.high
	}
	if a := b.tryPair.Load(); a != nil {
		return a.low, a.high
	}
	if b.rc.pair == nil {
		return "", ""
	}
	return b.rc.pair.live()
}

func (b *TCP) noteAttempt(low, high string) {
	if !b.attempted.CompareAndSwap(false, true) {
		return
	}
	b.tryPair.Store(&pairNow{low: low, high: high})
	b.st.write()
}

func (b *TCP) publishPair() {
	b.rc.liveFn = b.livePairNow
	b.st.setPair(b.rc.pairStatus)
}

func (b *TCP) dialTarget() string {
	if b.pp != nil {
		return b.pp.current()
	}
	return b.addr
}

func (b *TCP) lastSourceUsed() string {
	if s := b.lastSrc.Load(); s != nil {
		return *s
	}
	return ""
}

func (b *TCP) SetSourcePool(sp *PeerPool) {
	if b.isClient && !b.ws {
		b.sp = sp
		joinStatus(b.st, sp, "src")
		b.rc.bind(b.pp, sp)
		b.publishPair()
	}
}

func (b *TCP) sourceIP() string {
	if b.sp != nil {
		return b.sp.current()
	}
	return b.bindIP
}

func (b *TCP) livePath() (pathKey, bool) {
	var k pathKey
	c := b.curConn.Load()
	if c == nil {
		return k, false
	}
	k.Src, k.Sport = addrParts((*c).LocalAddr())
	k.Dst, k.Dport = addrParts((*c).RemoteAddr())
	if s := b.liveSNI.Load(); s != nil {
		k.SNI = *s
	}

	return k, b.cur.Load() != nil
}

func (b *TCP) endRound() { b.rc.success() }

func (b *TCP) rollSourcePort() bool {
	if c := b.curConn.Load(); c != nil {
		b.rolled.Store(true)
		(*c).Close()
	}
	b.st.portRedrawn()
	return true
}

func (b *TCP) ech() []byte {
	b.echMu.Lock()
	defer b.echMu.Unlock()
	return b.wsECH
}

func (b *TCP) setECH(ech []byte) bool {
	b.echMu.Lock()
	defer b.echMu.Unlock()
	if bytes.Equal(b.wsECH, ech) {
		return false
	}
	b.wsECH = ech
	return true
}

func (b *TCP) pinFailedOn(ip string) {
	if b.pool != nil {
		b.pool.pinCannotLand(ip)
	}
}

func (b *TCP) rotateDestTCP(proactive bool) (addr string, moved bool) {
	if b.pp == nil {
		return "", false
	}
	addr, moved = b.pp.nextEndpoint(proactive)
	if !moved {
		return addr, false
	}
	log.Printf("core/tcp: rotated destination to %s", addr)
	b.st.setActive(b.stTag + activeSep + addr)
	b.st.rotated("peer", "ip:"+addr, proactive)
	return addr, true
}

func (b *TCP) rotateSourceTCP(proactive bool) (addr string, moved bool) {
	if b.sp == nil {
		return "", false
	}
	addr, moved = b.sp.nextEndpoint(proactive)
	if !moved {
		return addr, false
	}

	log.Printf("core/tcp: rotated source to %s", addr)
	b.st.rotated("src", "ip:"+addr, proactive)
	return addr, true
}

func (b *TCP) SetDesync(on bool, ttl, count int, mode string) {
	if !b.isClient || !on {
		return
	}

	if ttl > injectMaxTTL {
		log.Printf("core/tcp: fake_ttl=%d is capped to %d on this carrier — its decoys ride the real connection's 4-tuple, so one that reached the server would draw an RST", ttl, injectMaxTTL)
	}
	b.dsOn, b.dsTTL, b.dsCount, b.dsMode = true, ttl, count, mode
}

func (b *TCP) SetSNISplit(on bool, pos int, mode string, ttl int) bool {
	if !b.isClient || !on || !b.ws {
		return false
	}
	b.sniSplit, b.splitPos, b.sniMode, b.splitTTL = true, pos, mode, ttl
	return true
}

func (b *TCP) fragWrap(conn net.Conn, host string, ech []byte) net.Conn {
	if b.sniSplit {
		return newFragConn(conn, host, b.splitPos, b.sniMode, b.splitTTL, len(ech) > 0, &b.dsSend)
	}
	return conn
}

func (b *TCP) SetStatusPath(path string) {
	if path == "" {
		return
	}

	carrier := "tcp"
	switch {
	case b.httpc:
		carrier = "http"
	case b.ws:
		carrier = "ws"
	case b.cover:
		carrier = "cover"
	}
	active := carrier + activeSep + b.addr
	if b.pool != nil {
		active = ""
	}
	b.st = newCoreStatus(path, active)
	b.stTag = carrier
	b.rc.attachStatus(b.st)
	if b.pool != nil {
		b.pool.attach(b.st.event, b.st.write)
		b.st.addHealth(b.pool.healthRows)
		b.rc.bindEdges(b.pool)
		b.publishPair()
	}
}

func (b *TCP) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	src := b.sourceIP()
	prev := b.lastSourceUsed()

	unbound := ""
	b.lastSrc.Store(&unbound)
	if src == "" {
		return d
	}
	ip := adoptableSource("tcp", b.sp, src, &b.srcWarned)
	if ip == nil {
		if b.sp != nil {
			b.sp.rejectCandidate(prev)
		}
		return d
	}
	d.LocalAddr = &net.TCPAddr{IP: ip}
	b.lastSrc.Store(&src)
	return d
}

func canBindSource(ip net.IP) bool {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func DialTCP(peerAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: connIdle, ping: pingEvery, isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

func DialWS(peerAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		ws: true, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: connIdle, ping: pingEvery, isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

func DialWSPool(dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, pool *wsPool, rotate time.Duration, httpc bool, httpcMode string) (*TCP, error) {
	b := &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		ws: true, wsTLS: true, httpc: httpc, httpcMode: httpcMode, pool: pool, rotate: rotate,
		idle: connIdle, ping: pingEvery, isClient: true, addr: "pool", closeCh: make(chan struct{})}
	b.rc.bindEdges(pool)
	return b, nil
}

func newWSPoolFromCfg(ips []string, snis []wsSNIEntry) *wsPool {
	if len(ips) == 0 || len(snis) == 0 {
		return nil
	}
	return newWSPool(ips, snis)
}

func DialHTTPC(peerAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte, httpcMode string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		ws: true, httpc: true, httpcMode: httpcMode, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: connIdle, ping: pingEvery, isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

func ListenHTTPC(listenAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		ws: true, httpc: true, idle: connIdle, ping: pingEvery, addr: listenAddr, ln: ln, lns: []net.Listener{ln}, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns), httpcSessions: make(map[string]*httpcSession)}, nil
}

func ListenWS(listenAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher, wsPath string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		ws: true, wsPath: wsPath, idle: connIdle, ping: pingEvery, addr: listenAddr, ln: ln, lns: []net.Listener{ln}, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}, nil
}

func ListenTCP(listenAddrs []string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	if len(listenAddrs) == 0 {
		return nil, errors.New("tcp listen: no listen address")
	}
	var lns []net.Listener
	for _, addr := range listenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return nil, err
		}
		lns = append(lns, ln)
	}
	b := &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: connIdle, ping: pingEvery, addr: listenAddrs[0], ln: lns[0], lns: lns, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}
	if cover {
		cs, err := tlscover.NewServer(psk, coverSNI)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return nil, err
		}

		cs.WarnIfDestUnreachable()
		b.coverSrv = cs
	}
	return b, nil
}

func (b *TCP) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- b.tunLoop() }()
	if b.isClient {
		go b.keepaliveLoop()
		go b.diagLoop()
		b.rc.port.setRoll(b.rollSourcePort)
		b.st.trackPath(b.livePath, b.closeCh)
		if b.rc.polls() {
			go b.peerPinPollLoop()
		}

		go func() {
			b.dialLoop()
			errc <- nil
		}()
	} else if b.httpc {
		go func() { b.runHTTPCServer(); errc <- nil }()
	} else {
		for i := 1; i < len(b.lns); i++ {
			go b.acceptLoopOn(b.lns[i])
		}
		go func() { b.acceptLoopOn(b.lns[0]); errc <- nil }()
	}
	return <-errc
}

func (b *TCP) writers() *tunWriters {
	b.twOnce.Do(func() { b.tw = newTunWriters([]*tun.Device{b.dev}) })
	return b.tw
}

func (b *TCP) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	close(b.closeCh)
	b.writers().close()
	if s := b.httpSrv.Load(); s != nil {
		s.Close()
	}
	for _, l := range b.lns {
		l.Close()
	}
	if c := b.cur.Load(); c != nil {
		c.conn.Close()
	}
	return nil
}

func (b *TCP) newFramer(conn net.Conn) *connFramer {
	return &connFramer{conn: conn, r: bufio.NewReaderSize(conn, readBufSize), obfs: b.obfs, psk: b.psk}
}

func (b *TCP) clientHandshake(cf *connFramer) error {
	ci, err := crypto.GenerateEphemeral()
	if err != nil {
		return err
	}
	if _, err := cf.conn.Write(crypto.InitMsg(b.psk, ci)); err != nil {
		return err
	}
	resp, err := crypto.ReadHandshake(cf.r, b.psk)
	if err != nil {
		return err
	}
	eResp, err := crypto.ParseResp(b.psk, ci.Pub, resp)
	if err != nil {
		return err
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, ci, eResp, ci.Pub, eResp, true)
	if err != nil {
		return err
	}
	cf.sealer = s
	return nil
}

func (b *TCP) serverHandshake(cf *connFramer) error {
	init, err := crypto.ReadHandshake(cf.r, b.psk)
	if err != nil {
		return err
	}
	eInit, err := crypto.ParseInit(b.psk, init)
	if err != nil {
		return err
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return err
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return err
	}
	cf.sealer = s
	_, err = cf.conn.Write(crypto.RespMsg(b.psk, eInit, sr))
	return err
}

func (b *TCP) acceptLoopOn(ln net.Listener) {
	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if b.closed.Load() {
				return
			}
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			log.Printf("core/tcp: accept error: %v (backoff %v)", err, backoff)
			if b.sleep(backoff) {
				return
			}
			continue
		}
		backoff = 0
		go b.handleServerConn(conn)
	}
}

func (b *TCP) handleServerConn(conn net.Conn) {
	select {
	case b.preAuth <- struct{}{}:
	default:
		conn.Close()
		return
	}
	acquired := true
	release := func() {
		if acquired {
			acquired = false
			<-b.preAuth
		}
	}
	defer release()

	if b.ws && !b.httpc {
		r, werr := wsServerHandshake(conn, b.wsPath, time.Now().Add(handshakeTimeout))
		if werr != nil {
			conn.Close()
			return
		}
		conn = &wsConn{Conn: conn, r: r, client: false}
	} else if b.cover {
		tconn, err := b.coverSrv.Handle(conn, time.Now().Add(handshakeTimeout))
		if err != nil {
			if err != tlscover.ErrProbe {
				conn.Close()
			}
			return
		}
		conn = tconn
	}
	cf := b.newFramer(conn)
	if !b.cryptoOn {
		log.Printf("core/tcp: peer connected from %s (clear)", conn.RemoteAddr())
		b.publishServerConn(cf)
		release()
		b.serve(cf)
		return
	}

	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if err := b.serverHandshake(cf); err != nil {
		conn.Close()
		return
	}
	typ, session, seq, payload, err := cf.readFrame()
	if err != nil || !cf.rp.ok(session, seq) {
		conn.Close()
		return
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil {
			conn.Close()
			return
		}
	}
	log.Printf("core/tcp: peer connected from %s", conn.RemoteAddr())
	b.publishServerConn(cf)
	release()
	b.handleFrame(cf, typ, payload)
	if b.obfs {
		_ = cf.flushSalt()
	}
	b.serve(cf)
}

func (b *TCP) publishServerConn(cf *connFramer) {
	b.cur.CompareAndSwap(nil, cf)
	b.authMu.Lock()
	b.authConns = append(b.authConns, cf)
	cur := b.cur.Load()
	var reap []*connFramer
	for len(b.authConns) > maxAuthConns {
		idx := -1
		for i, c := range b.authConns {
			if c != cur {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		reap = append(reap, b.authConns[idx])
		b.authConns = append(b.authConns[:idx], b.authConns[idx+1:]...)
	}
	b.authMu.Unlock()
	for _, v := range reap {
		if v == b.cur.Load() {
			b.authMu.Lock()
			b.authConns = append(b.authConns, v)
			b.authMu.Unlock()
			continue
		}
		v.conn.Close()
	}
}

func (b *TCP) reelectDownstream() {
	b.authMu.Lock()
	var pick *connFramer
	if n := len(b.authConns); n > 0 {
		pick = b.authConns[n-1]
	}
	b.authMu.Unlock()
	if pick != nil {
		b.cur.CompareAndSwap(nil, pick)
	}
}

func (b *TCP) removeAuthConn(cf *connFramer) {
	b.authMu.Lock()
	for i, c := range b.authConns {
		if c == cf {
			b.authConns = append(b.authConns[:i], b.authConns[i+1:]...)
			break
		}
	}
	b.authMu.Unlock()
}

func (b *TCP) noteECHSelfHeal(host string, ech []byte) {
	detail := host + " " + base64.StdEncoding.EncodeToString(ech)
	if b.pool != nil {
		if b.pool.updateECH(host, ech) {
			b.pool.event("ech", "self_heal", detail)
		}
		return
	}

	if b.setECH(ech) {
		b.st.event("ech", "self_heal", detail)
	}
}

func (b *TCP) tlsToEdge(conn net.Conn, dialAddr, host string, ech []byte, live bool, budget time.Duration) (net.Conn, error) {
	var err error
	healed := false
	for attempt := 0; attempt < 2; attempt++ {
		var uc net.Conn

		uc, err = uEdgeHandshake(b.fragWrap(conn, host, ech), host, ech, []string{"http/1.1"}, false, budget)
		if err == nil {
			if healed && live {
				b.noteECHSelfHeal(host, ech)
			}
			return uc, nil
		}
		conn.Close()
		var echErr *utls.ECHRejectionError
		if attempt == 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList
			log.Printf("core/ws: ECH-SELFHEAL[reactive/in-band] for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			healed = true
			if conn, err = b.dialer(budget).Dial("tcp", dialAddr); err != nil {
				return nil, err
			}

			b.sendTCPFakes(conn)
			continue
		}
		break
	}
	return nil, err
}

func uEdgeHandshake(conn net.Conn, host string, ech []byte, alpn []string, goFingerprint bool, budget time.Duration) (net.Conn, error) {
	cfg := &utls.Config{ServerName: host}
	var echPub []string

	echRejected := false
	if len(ech) > 0 {
		cfg.EncryptedClientHelloConfigList = ech
		echPub = echPublicNames(ech)
		if len(echPub) > 0 {
			cfg.EncryptedClientHelloRejectionVerify = func(utls.ConnectionState) error {
				echRejected = true
				return nil
			}
		}
	}
	var uc *utls.UConn
	var err error
	if goFingerprint {
		cfg.NextProtos = alpn
		uc = utls.UClient(conn, cfg, utls.HelloGolang)
	} else {
		uc = utls.UClient(conn, cfg, utls.HelloCustom)
		var spec utls.ClientHelloSpec
		if spec, err = chromeSpec(alpn); err != nil {
			return nil, err
		}
		if err = uc.ApplyPreset(&spec); err != nil {
			return nil, err
		}
	}
	conn.SetDeadline(time.Now().Add(budget))
	if err = uc.Handshake(); err != nil {
		var echErr *utls.ECHRejectionError
		if len(echPub) > 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			if verr := verifyECHPublicName(uc.ConnectionState().PeerCertificates, echPub); verr != nil {
				return nil, fmt.Errorf("ech-reject: outer cert not valid for %v: %w", echPub, verr)
			}
		}
		return nil, err
	}

	if echRejected {
		uc.Close()
		return nil, errors.New("ech-reject: handshake completed with an unverified outer certificate")
	}
	conn.SetDeadline(time.Time{})
	return uc, nil
}

const echConfigVersion uint16 = 0xfe0d

func echPublicNames(list []byte) []string {
	s := cryptobyte.String(list)
	var configs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&configs) {
		return nil
	}
	var names []string
	for !configs.Empty() {
		var version uint16
		var contents cryptobyte.String
		if !configs.ReadUint16(&version) || !configs.ReadUint16LengthPrefixed(&contents) {
			return nil
		}
		if version != echConfigVersion {
			continue
		}
		var configID, maxNameLen uint8
		var kemID uint16
		var publicKey, cipherSuites, publicName cryptobyte.String
		if !contents.ReadUint8(&configID) || !contents.ReadUint16(&kemID) ||
			!contents.ReadUint16LengthPrefixed(&publicKey) || !contents.ReadUint16LengthPrefixed(&cipherSuites) ||
			!contents.ReadUint8(&maxNameLen) || !contents.ReadUint8LengthPrefixed(&publicName) {
			return nil
		}
		if name := string(publicName); name != "" {
			names = append(names, name)
		}
	}
	return names
}

var echVerifyRoots *x509.CertPool

func verifyECHPublicName(certs []*x509.Certificate, publicNames []string) error {
	if len(publicNames) == 0 {
		return errors.New("ech-reject: no ECH public name to verify against")
	}
	var last error
	for _, n := range publicNames {
		if err := verifyOuterCert(certs, n, echVerifyRoots); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return last
}

func verifyOuterCert(certs []*x509.Certificate, publicName string, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return errors.New("ech-reject: no peer certificate")
	}
	opts := x509.VerifyOptions{Roots: roots, DNSName: publicName, Intermediates: x509.NewCertPool()}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(opts)
	return err
}

func chromeSpec(alpn []string) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, err
	}
	if alpn != nil {
		for _, ext := range spec.Extensions {
			if a, ok := ext.(*utls.ALPNExtension); ok {
				a.AlpnProtocols = alpn
			}
		}
	}
	return spec, nil
}

func (b *TCP) establishWS() (net.Conn, string, string, error) {
	dialAddr, host, ech, path := b.addr, b.wsHost, b.ech(), b.wsPath
	if b.pool != nil {
		ip, sni, ok := b.pool.current()
		if !ok {
			return nil, "", "", errors.New("ws: edge pool is empty")
		}
		dialAddr, host, ech, path = ip, sni.host, sni.ech, sni.path
	}
	if host == "" {
		host = dialAddr
	}
	b.noteAttempt(dialAddr, host)
	conn, err := b.dialer(connectTimeout).Dial("tcp", dialAddr)
	if err != nil {
		b.pinFailedOn(dialAddr)
		return nil, dialAddr, "", err
	}

	b.sendTCPFakes(conn)
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, dialAddr, host, ech, true, handshakeTimeout)
		if terr != nil {
			return nil, dialAddr, "", terr
		}
		conn = tc
	}
	r, werr := wsClientHandshake(conn, host, path, time.Now().Add(handshakeTimeout))
	if werr != nil {
		conn.Close()
		return nil, dialAddr, "", werr
	}
	return &wsConn{Conn: conn, r: r, client: true}, dialAddr, activeLabel(dialAddr, host), nil
}

func (b *TCP) setLastErr(err error) {
	if err == nil {
		return
	}
	s := err.Error()
	if strings.Contains(s, "use of closed network connection") {
		return
	}
	b.lastErr.Store(s)
}

func (b *TCP) takeLastErr() string {
	s, _ := b.lastErr.Load().(string)
	b.lastErr.Store("")
	return s
}

func classifyErr(s string) string {
	l := strings.ToLower(s)
	switch {
	case s == "":
		return "closed"
	case strings.Contains(l, "keepalive") || strings.Contains(l, "ping"):
		return "ping_timeout"
	case strings.Contains(l, "connection reset") || strings.Contains(l, "reset by peer"):
		return "reset"
	case strings.Contains(l, "refused"):
		return "refused"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline") || strings.Contains(l, "no route") || strings.Contains(l, "unreachable"):
		return "timeout"
	case strings.Contains(l, "eof"):
		return "eof"
	case strings.Contains(l, "tls") || strings.Contains(l, "handshake") || strings.Contains(l, "certificate"):
		return "tls"
	case strings.Contains(l, "websocket") || strings.Contains(l, "ws ") || strings.Contains(l, "101 switching") || strings.Contains(l, "upgrade"):
		return "ws_upgrade"
	default:
		return "dropped"
	}
}

func (b *TCP) readECHCmd() []string {
	if !b.ws || b.st == nil {
		return nil
	}
	cp := b.st.echCmdPath()
	data, err := os.ReadFile(cp)
	if err != nil {
		return nil
	}
	os.Remove(cp)
	var c struct {
		SNIs map[string]string `json:"snis"`
	}
	if json.Unmarshal(data, &c) != nil || len(c.SNIs) == 0 {
		return nil
	}
	if b.pool != nil {
		return b.pool.applyECH(c.SNIs)
	}
	if b.wsHost == "" {
		return nil
	}
	b64, ok := c.SNIs[b.wsHost]
	if !ok {
		return nil
	}
	ech, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if derr != nil || len(ech) == 0 || !b.setECH(ech) {
		return nil
	}
	return []string{b.wsHost}
}

const (
	reconnectBase = 1 * time.Second
	reconnectMax  = 60 * time.Second
)

func nextReconnectDelay(cur time.Duration) time.Duration {
	next := reconnectBase
	if cur > 0 {
		if next = cur * 2; next > reconnectMax {
			next = reconnectMax
		}
	}
	return jitterFrac(next)
}

func (b *TCP) dialLoop() {
	backoff := time.Duration(0)

	youngDeaths := 0
	for {
		if b.closed.Load() {
			return
		}
		if b.pool == nil && len(b.readECHCmd()) > 0 {
			log.Printf("core/ws: live ECH key updated for %s (single edge, no rebuild)", b.wsHost)
		}

		conn, label, combo, err := b.dialCarrier()
		if err != nil {
			backoff = nextReconnectDelay(backoff)
			if b.sleep(backoff) {
				return
			}
			continue
		}
		cf, err := b.handshakeAndPrime(conn)
		if err != nil {
			conn.Close()
			backoff = nextReconnectDelay(backoff)
			if b.sleep(backoff) {
				return
			}
			continue
		}
		log.Printf("core/tcp: connected to %s", label)
		backoff = 0
		connectedAt := time.Now()

		b.manualSwitch.Store(false)
		b.cur.Store(cf)
		b.adoptRx(cf)
		cc := conn
		b.curConn.Store(&cc)
		b.st.newSession()
		if b.pool != nil {
			sni := strings.TrimPrefix(combo, label+activeSep)
			b.liveSNI.Store(&sni)

			b.livePair.Store(&pairNow{low: label, high: sni})
			b.st.setActive(combo)

			b.pool.pinLandedOn(label, sni)
		} else {
			b.livePair.Store(&pairNow{low: label, high: b.lastSourceUsed()})
			if b.pp != nil {
				b.pp.pinLandedOn(label)
			}
			if b.sp != nil {
				b.sp.pinLandedOn(b.lastSourceUsed())
			}
		}

		back := label
		if combo != "" {
			back = combo
		}
		b.st.reconnected(back)

		var rot *time.Timer
		var rotated atomic.Bool

		var rotp atomic.Pointer[time.Timer]
		rearm := func(d time.Duration) {
			if t := rotp.Load(); t != nil {
				t.Reset(d)
			}
		}

		var timerLive atomic.Bool
		timerLive.Store(true)
		if b.pool != nil && b.rotate > 0 {
			c := conn

			rot = time.AfterFunc(b.rotate, func() {
				if !timerLive.Load() {
					return
				}
				if b.pool.isPinned() {
					rearm(b.rotate)
					return
				}

				prevIP, prevSNI, ok := b.pool.current()
				if !ok || !b.pool.advance() {
					rearm(b.rotate)
					return
				}

				nowIP, nowSNI, _ := b.pool.current()
				if nowIP != prevIP {
					b.st.rotated("edge", "ip:"+nowIP, true)
				}
				if nowSNI.host != prevSNI.host {
					b.st.rotated("sni", "sni:"+nowSNI.host, true)
				}
				rotated.Store(true)
				c.Close()
			})
			rotp.Store(rot)
		} else if (b.pp != nil && b.pp.rotate > 0) || (b.sp != nil && b.sp.rotate > 0) {
			c := conn
			iv := time.Duration(0)
			if b.pp != nil {
				iv = b.pp.rotate
			}
			if b.sp != nil && b.sp.rotate > iv {
				iv = b.sp.rotate
			}

			rot = time.AfterFunc(iv, func() {
				if !timerLive.Load() {
					return
				}
				if (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned()) {
					rearm(iv)
					return
				}

				dstMoved := false
				lap := true
				if b.pp != nil {
					_, dstMoved = b.rotateDestTCP(true)
					lap = b.rc.od.beat(dstMoved, b.pp.eligibleCount)
				}
				moved := dstMoved
				if lap {
					if _, m := b.rotateSourceTCP(true); m {
						moved = true
					}
				}
				if !moved {
					rearm(iv)
					return
				}
				rotated.Store(true)
				c.Close()
			})
			rotp.Store(rot)
		}
		b.serve(cf)
		timerLive.Store(false)
		if rot != nil {
			rot.Stop()
		}
		b.curConn.CompareAndSwap(&cc, nil)
		b.liveSNI.Store(nil)

		b.tryPair.Store(b.livePair.Swap(nil))
		b.attempted.Store(false)
		b.cur.CompareAndSwap(cf, nil)

		deliberate := false

		if !b.closed.Load() {
			var cause string
			if b.pool != nil {
				cause = b.takeLastErr()
			}
			switch {
			case b.rolled.Swap(false):
				deliberate = true
			case b.manualSwitch.Swap(false) || rotated.Load():
				deliberate = true
				b.endRound()
			case b.pool != nil || b.pp != nil || b.sp != nil:
				if b.pool != nil {
					b.st.down(classifyErr(cause), label)
				}

				if time.Since(connectedAt) >= minLiveness {
					youngDeaths = 0
					b.endRound()
				} else if b.pool != nil && youngDeaths < b.pool.comboCount() && b.pool.advance() {
					if youngDeaths == 0 {
						b.pool.event("down", "edge-walk", "ws")
					}
					youngDeaths++
				}
			}
		}

		if b.st != nil && !deliberate && !b.closed.Load() {
			b.st.down(classifyErr(b.takeLastErr()), label)
		}

		if !deliberate {
			backoff = nextReconnectDelay(backoff)
			if b.sleep(backoff) {
				return
			}
		}
	}
}

func (b *TCP) dialCarrier() (net.Conn, string, string, error) {
	if b.ws {
		var c net.Conn
		var edge, combo string
		var err error
		if b.httpc {
			c, edge, combo, err = b.establishHTTPC()
		} else {
			c, edge, combo, err = b.establishWS()
		}
		if err != nil {
			log.Printf("core/ws: connect via %s failed: %v", edge, err)
			return nil, edge, "", err
		}
		return c, edge, combo, nil
	}
	target := b.dialTarget()
	b.noteAttempt(target, b.sourceIP())
	c, err := b.dialer(connectTimeout).Dial("tcp", target)
	if err != nil {
		log.Printf("core/tcp: dial %s failed: %v", target, err)
		return nil, target, "", err
	}

	b.sendTCPFakes(c)
	if b.cover {
		tconn, cerr := tlscover.ClientConn(c, b.coverSNI, b.psk, time.Now().Add(handshakeTimeout))
		if cerr != nil {
			c.Close()
			log.Printf("core/tcp: tls cover to %s failed: %v", target, cerr)
			return nil, target, "", cerr
		}
		c = tconn
	}
	return c, target, target, nil
}

func (b *TCP) coverProbeHint() {
	if !b.cover {
		return
	}
	b.coverHint.Do(func() {
		log.Printf("core/tcp: the TLS cover handshake to %s succeeded but the core handshake behind it did not. "+
			"The cover server answers an unopenable auth token by proxying to the real cover site — which is what "+
			"makes it probe-resistant — so this looks identical to a censor probe from here. The two causes are a "+
			"PSK mismatch and a clock skew over %ds between the ends; check the clocks first (this host: %s)",
			b.coverSNI, tlscover.AuthWindowSecs(), time.Now().UTC().Format(time.RFC3339))
	})
}

func (b *TCP) handshakeAndPrime(conn net.Conn) (*connFramer, error) {
	cf := b.newFramer(conn)
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if b.cryptoOn {
		if err := b.clientHandshake(cf); err != nil {
			b.coverProbeHint()
			return nil, err
		}

		cf.rxAt.Store(time.Now().UnixNano())
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil {
			return nil, err
		}
	}

	if err := cf.writeFrame(typePing, nil); err != nil {
		return nil, err
	}

	return cf, nil
}

func (b *TCP) peerPinPollLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			b.pollPeerCmd()
		}
	}
}

func (b *TCP) dropCarrier() {
	b.manualSwitch.Store(true)
	if c := b.curConn.Load(); c != nil {
		(*c).Close()
	}
}

func (b *TCP) pollPeerCmd() {
	if b.rc.poll(b.rotateLowTCP, b.rotateHighTCP, b.pinApplied, b.st.pathEpoch) {
		b.dropCarrier()
	}
	if hosts := b.readECHCmd(); len(hosts) > 0 {
		log.Printf("core/ws: live ECH key updated for %v (no rebuild)", hosts)
	}
}

func (b *TCP) rotateLowTCP(proactive bool) {
	if b.pool == nil {
		b.rotateDestTCP(proactive)
		return
	}
	low, _ := b.rc.underJudgement()
	b.pool.markSuspect("ip", low, "tun-probe")

	if now := b.pool.advanceIP(); now != "" {
		b.st.rotated("edge", "ip:"+now, proactive)
	}
}

func (b *TCP) rotateHighTCP(proactive bool) {
	if b.pool == nil {
		b.rotateSourceTCP(proactive)
		return
	}

	_, sni := b.rc.underJudgement()
	b.pool.markSuspect("sni", sni, "tun-probe")
	if now := b.pool.advanceSNI(); now != "" {
		b.st.rotated("sni", "sni:"+now, proactive)
	}
}

func (b *TCP) pinApplied(kind, key string) {
	if b.pool == nil && kind == "dst" {
		b.st.setActive(b.stTag + activeSep + key)
	}
}

func (b *TCP) handleFrame(cf *connFramer, typ byte, payload []byte) {
	switch typ {
	case typePing:
		_ = cf.writeFrame(typePong, nil)
	case typePong:
	case typeData:
		b.lastRxData.Store(time.Now().UnixNano())

		if !b.isClient {
			b.cur.Store(cf)
		}
		b.writers().write(payload)
	}
}

func (b *TCP) serve(cf *connFramer) {
	b.onConnErr(cf, b.readLoop(cf))
}

func (b *TCP) adoptRx(cf *connFramer) {
	if cf == nil {
		return
	}
	rx := cf.rxAt.Load()
	for {
		old := b.lastRx.Load()
		if rx <= old || b.lastRx.CompareAndSwap(old, rx) {
			return
		}
	}
}

func (b *TCP) readLoop(cf *connFramer) error {
	for {
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
		typ, session, seq, payload, err := cf.readFrame()
		if err != nil {
			return err
		}
		if cf.sealer != nil && !cf.rp.ok(session, seq) {
			continue
		}
		now := time.Now().UnixNano()
		cf.rxAt.Store(now)

		if cf == b.cur.Load() {
			b.lastRx.Store(now)
		}
		b.handleFrame(cf, typ, payload)
	}
}

func (b *TCP) onConnErr(cf *connFramer, err error) {
	if b.isClient {
		b.setLastErr(err)
	}
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil)
	b.removeAuthConn(cf)
	if !b.isClient {
		b.reelectDownstream()
	}
	if !b.closed.Load() {
		log.Printf("core/tcp: connection closed: %v", err)
	}
}

func (b *TCP) tunLoop() error {
	buf := make([]byte, maxDatagram)
	frames := make([][]byte, 0, tunBatchFrames)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if b.closed.Load() {
				return nil
			}

			log.Printf("core/tcp: tun read error: %v", err)
			return err
		}
		cf := b.cur.Load()
		if cf == nil {
			continue
		}
		frames = frames[:0]
		frames = b.appendFrame(cf, frames, buf[:n])
		for len(frames) < cap(frames) && b.cur.Load() == cf {
			m, ok, err := b.dev.TryRead(buf)
			if err != nil || !ok {
				break
			}
			frames = b.appendFrame(cf, frames, buf[:m])
		}
		err = cf.writeAll(frames)
		clear(frames)
		if err != nil {
			b.onConnErr(cf, err)
			continue
		}
	}
}

func (b *TCP) appendFrame(cf *connFramer, frames [][]byte, pkt []byte) [][]byte {
	f, err := cf.frame(typeData, pkt)
	if err != nil {
		if errors.Is(err, errFrameTooBig) {
			log.Printf("core/tcp: dropping oversize packet (%d bytes) — too large to frame", len(pkt))
			return frames
		}
		log.Printf("core/tcp: frame error: %v", err)
		return frames
	}
	return append(frames, f)
}

func (b *TCP) diagLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			log.Printf("core/tcp: health — goroutines=%d", runtime.NumGoroutine())
		}
	}
}

func (b *TCP) keepaliveLoop() {
	for {
		select {
		case <-b.closeCh:
			return
		case <-time.After(keepaliveInterval(b.ping, b.psk)):
			if cf := b.cur.Load(); cf != nil && !b.recentData() {
				if err := b.pingOne(cf); err != nil {
					b.onConnErr(cf, err)
				}
			}
		}
	}
}

func (b *TCP) pingOne(cf *connFramer) error { return cf.writeFrame(typePing, nil) }

func (b *TCP) recentData() bool {
	last := b.lastRxData.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) < b.ping
}

func (b *TCP) sleep(d time.Duration) bool {
	select {
	case <-b.closeCh:
		return true
	case <-time.After(d):
		return false
	}
}

type pairNow struct{ low, high string }
