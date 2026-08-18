package tlscover

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	utls "github.com/refraction-networking/utls"
)

const (
	authMagic  = "TNLR"
	authWindow = 120
	maxRelays  = 256
	maxWaiting = 256
	relayWait  = 10 * time.Second
	relayIdle  = 120 * time.Second
)

var ErrProbe = errors.New("tlscover: probe proxied to dest")

var (
	errNotTLS   = errors.New("tlscover: not a TLS handshake")
	errBadHello = errors.New("tlscover: malformed ClientHello")
)

func authKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|reality-auth|" + psk))
	return k[:]
}

func sealToken(psk string, ts int64) ([]byte, error) {
	a, err := chacha20poly1305.New(authKey(psk))
	if err != nil {
		return nil, err
	}
	nonce8 := make([]byte, 8)
	if _, err := rand.Read(nonce8); err != nil {
		return nil, err
	}
	pt := make([]byte, 8)
	copy(pt, authMagic)
	binary.BigEndian.PutUint32(pt[4:], uint32(ts))
	var nonce [12]byte
	copy(nonce[:], nonce8)
	return append(nonce8, a.Seal(nil, nonce[:], pt, nil)...), nil
}

func AuthWindowSecs() int { return authWindow }

func openToken(psk string, sid []byte) bool {
	if len(sid) != 32 {
		return false
	}
	a, err := chacha20poly1305.New(authKey(psk))
	if err != nil {
		return false
	}
	var nonce [12]byte
	copy(nonce[:], sid[:8])
	pt, err := a.Open(nil, nonce[:], sid[8:], nil)
	if err != nil || len(pt) != 8 || string(pt[:4]) != authMagic {
		return false
	}
	ts := int64(binary.BigEndian.Uint32(pt[4:8]))
	now := time.Now().Unix()
	return ts >= now-authWindow && ts <= now+authWindow
}

func ClientConn(raw net.Conn, sni, psk string, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	u := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	tok, err := sealToken(psk, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = tok
	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	if err := u.Handshake(); err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		_ = raw.SetDeadline(time.Time{})
	}
	return u, nil
}

type Server struct {
	cert  *tls.Certificate
	psk   string
	dest  string
	relay chan struct{}
	queue chan struct{}
	idle  time.Duration

	mu   sync.Mutex
	seen map[[32]byte]int64

	dialFail atomic.Int64
	dialN    atomic.Int64
}

const dialFailEvery = 60 * time.Second

func (sv *Server) noteDialFail(err error) {
	sv.dialN.Add(1)
	now := time.Now().UnixNano()
	prev := sv.dialFail.Load()
	if prev != 0 && now-prev < int64(dialFailEvery) {
		return
	}
	if !sv.dialFail.CompareAndSwap(prev, now) {
		return
	}
	n := sv.dialN.Swap(0)
	more := ""
	if n > 1 {
		more = fmt.Sprintf(" (+%d more in the last %s)", n-1, dialFailEvery)
	}
	log.Printf("core/cover: cover site %s is UNREACHABLE from this server (%v)%s — every probe now gets a "+
		"bare close instead of that site's real answer, so the cover proves nothing", sv.dest, err, more)
}

func NewServer(psk, destHost string) (*Server, error) {
	cert, err := SelfSignedCert(destHost)
	if err != nil {
		return nil, err
	}
	return &Server{cert: cert, psk: psk, dest: net.JoinHostPort(destHost, "443"),
		relay: make(chan struct{}, maxRelays), queue: make(chan struct{}, maxWaiting),
		idle: relayIdle, seen: map[[32]byte]int64{}}, nil
}

func (sv *Server) WarnIfDestUnreachable() {
	dest := sv.dest
	go func() {
		c, err := net.DialTimeout("tcp", dest, 8*time.Second)
		if err != nil {
			log.Printf("core/cover: cover site %s did not answer at startup (%v) — while it stays "+
				"unreachable a prober gets a bare close, not that site's real TLS answer. Pick a cover "+
				"domain this server can actually reach.", dest, err)
			return
		}
		_ = c.Close()
	}()
}

func (sv *Server) Handle(raw net.Conn, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}

	hello, sid, err := readClientHello(raw)
	if err == nil && openToken(sv.psk, sid) && sv.firstSight(sid) {
		if !deadline.IsZero() {
			_ = raw.SetDeadline(time.Time{})
		}
		pc := &prefixConn{Conn: raw, pre: hello}

		s := tls.Server(pc, &tls.Config{Certificates: []tls.Certificate{*sv.cert}, MinVersion: tls.VersionTLS13})
		if !deadline.IsZero() {
			_ = s.SetDeadline(deadline)
		}
		if err := s.Handshake(); err != nil {
			return nil, err
		}
		_ = s.SetDeadline(time.Time{})
		return s, nil
	}

	sv.proxyToDest(raw, hello)
	return nil, ErrProbe
}

func (sv *Server) firstSight(token []byte) bool {
	var k [32]byte
	copy(k[:], token)
	now := time.Now().Unix()
	sv.mu.Lock()
	defer sv.mu.Unlock()
	for kk, exp := range sv.seen {
		if exp < now {
			delete(sv.seen, kk)
		}
	}
	if _, ok := sv.seen[k]; ok {
		return false
	}
	sv.seen[k] = now + authWindow*2
	return true
}

func (sv *Server) proxyToDest(raw net.Conn, hello []byte) {
	select {
	case sv.queue <- struct{}{}:
	default:
		raw.Close()
		return
	}
	go func() {

		queued := true
		leaveQueue := func() {
			if queued {
				queued = false
				<-sv.queue
			}
		}
		defer leaveQueue()
		t := time.NewTimer(relayWait)
		defer t.Stop()
		select {
		case sv.relay <- struct{}{}:
			leaveQueue()
		case <-t.C:
			raw.Close()
			return
		}
		defer func() { <-sv.relay }()
		dst, err := net.DialTimeout("tcp", sv.dest, 8*time.Second)
		if err != nil {
			sv.noteDialFail(err)
			raw.Close()
			return
		}

		ri, di := &idleConn{Conn: raw, idle: sv.idle}, &idleConn{Conn: dst, idle: sv.idle}
		if _, err := di.Write(hello); err != nil {
			dst.Close()
			raw.Close()
			return
		}
		done := make(chan struct{}, 2)
		go func() { io.Copy(di, ri); done <- struct{}{} }()
		go func() { io.Copy(ri, di); done <- struct{}{} }()
		<-done
		dst.Close()
		raw.Close()
	}()
}

type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(b)
}

func readClientHello(c net.Conn) (buf, sid []byte, err error) {

	hdr := make([]byte, 5)
	n, err := io.ReadFull(c, hdr)
	buf = hdr[:n]
	if err != nil {
		return buf, nil, err
	}
	if hdr[0] != 0x16 {
		return buf, nil, errNotTLS
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 40 || recLen > 16384 {
		return buf, nil, errBadHello
	}
	body := make([]byte, recLen)
	n, err = io.ReadFull(c, body)
	buf = append(buf, body[:n]...)
	if err != nil {
		return buf, nil, err
	}

	if len(body) < 39 || body[0] != 0x01 {
		return buf, nil, errBadHello
	}
	sidLen := int(body[38])
	if 39+sidLen > len(body) {
		return buf, nil, errBadHello
	}
	sid = body[39 : 39+sidLen]
	return buf, sid, nil
}

type prefixConn struct {
	net.Conn
	pre []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pre) > 0 {
		n := copy(b, p.pre)
		p.pre = p.pre[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func SelfSignedCert(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
