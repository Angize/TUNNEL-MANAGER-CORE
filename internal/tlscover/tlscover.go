// Package tlscover gives a core TCP connection a REALITY-style TLS cover, so it not only looks like
// HTTPS to passive DPI but survives ACTIVE probing — the censor connecting to the server itself and
// comparing. The client speaks a Chrome-fingerprinted ClientHello (uTLS) with a PSK-authenticated token
// hidden in the 32-byte legacy session id, which is normally random and therefore invisible:
//
//	token valid (our client)   the server terminates TLS itself and the core/PSK handshake runs inside
//	token absent or invalid    the server transparently PROXIES the whole connection to the REAL
//	                           dest:443 and relays bytes, so the prober gets that site's genuine
//	                           certificate and real response
//
// So dest MUST be a real, reachable, unblocked HTTPS site — it is the cover the server borrows. Replays
// are neutralised by a timestamp window plus a seen-ClientHello cache, and cannot complete the inner
// PSK handshake anyway.
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
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	utls "github.com/refraction-networking/utls"
)

const (
	authMagic  = "TNLR"            // 4 bytes; marks a genuine token after decryption
	authWindow = 120               // seconds a token stays valid (replay bound)
	maxRelays  = 256               // concurrent probe→dest relays cap
	maxWaiting = 256               // probes queued for a relay slot
	relayWait  = 10 * time.Second  // how long a queued probe waits for a slot
	relayIdle  = 120 * time.Second // no byte either way for this long ⇒ tear the relay down
)

// ErrProbe means the connection was not an authenticated client and has been
// handed off to the dest-proxy relay; the caller must abandon it (do not close).
var ErrProbe = errors.New("tlscover: probe proxied to dest")

var (
	errNotTLS   = errors.New("tlscover: not a TLS handshake")
	errBadHello = errors.New("tlscover: malformed ClientHello")
)

func authKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|reality-auth|" + psk))
	return k[:]
}

// sealToken builds the 32-byte session-id token: a fresh 8-byte random nonce carried in the
// clear, followed by AEAD(magic4 || ts32) keyed by the PSK. The nonce is random per seal —
// deriving it from the ClientHello random (as before) gave no per-message uniqueness guarantee
// for the fixed-key AEAD. Layout: 8 nonce + (8 pt + 16 tag) = 32 bytes.
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

// AuthWindowSecs is the clock skew the auth token tolerates, in seconds. Exported so the carrier can
// name the real number when it reports the one symptom a skewed clock produces: a TLS handshake that
// succeeds into the REAL cover site (the server's answer to an unopenable token, and to a probe)
// while the core handshake behind it fails with nothing pointing at the clock.
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

// ClientConn performs the Chrome-mimicking TLS handshake, embedding the auth
// token so the server terminates locally instead of proxying us to dest.
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

// Server is the REALITY-style responder: it authenticates clients by the token
// in their ClientHello and proxies everyone else to the real dest.
type Server struct {
	cert  *tls.Certificate
	psk   string
	dest  string // host:port of the real site to borrow
	relay chan struct{}
	queue chan struct{}
	idle  time.Duration // relay idle bound; a field only so tests can shorten it

	mu         sync.Mutex
	seen       map[[32]byte]int64 // session-id token -> expiry (anti-replay)
	destLogged int64              // unix-seconds of the last "cannot reach dest" line (rate limit)
}

// NewServer builds a cover server that borrows destHost (its :443 is proxied to
// for any non-authenticated connection).
func NewServer(psk, destHost string) (*Server, error) {
	cert, err := SelfSignedCert(destHost)
	if err != nil {
		return nil, err
	}
	return &Server{cert: cert, psk: psk, dest: net.JoinHostPort(destHost, "443"),
		relay: make(chan struct{}, maxRelays), queue: make(chan struct{}, maxWaiting),
		idle: relayIdle, seen: map[[32]byte]int64{}}, nil
}

// CheckDest says out loud, once, whether the cover site can be reached AT ALL from this server. Nothing
// about the cover works without that: every unauthenticated connection is relayed to dest, so when dest
// is unreachable proxyToDest can only close -- and an instant FIN right after a ClientHello is the exact
// distinguisher this whole path exists to deny a censor. A foreign cover domain on an Iran-side server is
// the ordinary way to end up there, and it used to be silent.
//
// The CALLER starts it, when the server goes into service. Not the constructor: one that spawns a
// goroutine reading its own fields races whoever finishes configuring the value afterwards.
func (sv *Server) CheckDest() {
	c, err := net.DialTimeout("tcp", sv.dest, 8*time.Second)
	if err != nil {
		log.Printf("cover: the cover site %s is UNREACHABLE from this server (%v) — every probe will be "+
			"closed on the spot instead of relayed, which is the fingerprint the cover exists to remove. "+
			"Set cover_sni to a site this server can actually reach.", sv.dest, err)
		return
	}
	c.Close()
	log.Printf("cover: borrowing %s (reachable)", sv.dest)
}

// destUnreachable reports a relay dial failure, at most one line a minute. Rate-limited on purpose: a
// censor scanning the port would otherwise turn this into its own log amplifier, and one line a minute
// is enough to tell an operator the cover is down.
func (sv *Server) destUnreachable(err error) {
	now := time.Now().Unix()
	sv.mu.Lock()
	quiet := now < sv.destLogged+60
	if !quiet {
		sv.destLogged = now
	}
	sv.mu.Unlock()
	if !quiet {
		log.Printf("cover: cannot reach the cover site %s (%v) — probes are being closed on the spot "+
			"instead of relayed to it", sv.dest, err)
	}
}

// Handle reads the ClientHello and either returns a TLS conn (authenticated
// client) or proxies the connection to dest and returns ErrProbe.
func (sv *Server) Handle(raw net.Conn, deadline time.Time) (net.Conn, error) {
	if !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}
	// readClientHello returns the bytes it consumed even on error, so hello is
	// always safe to replay to dest below.
	hello, sid, err := readClientHello(raw)
	if err == nil && openToken(sv.psk, sid) && sv.firstSight(sid) {
		if !deadline.IsZero() {
			_ = raw.SetDeadline(time.Time{})
		}
		pc := &prefixConn{Conn: raw, pre: hello}
		// Pin TLS 1.3: our Chrome-fingerprinted client always offers it, and in
		// 1.3 the server Certificate message is encrypted — so the throwaway
		// self-signed cert is never visible to a passive observer (only the real
		// dest's genuine cert, for proxied probes, is ever seen on the wire).
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
	// Everything that is not a successfully-authenticated token — an unreadable hello (fragmented,
	// multi-record, oversized, or non-TLS), an absent or invalid token, or a replay — MUST be proxied to
	// dest, replaying whatever bytes we consumed. Dropping the connection here would hand a censor a
	// distinguisher; a probe or a real browser has to see the genuine dest site instead.
	sv.proxyToDest(raw, hello)
	return nil, ErrProbe
}

// firstSight records a token (the ClientHello session-id) and reports whether it is new (a
// replay — the same token in ANY hello, since the token now carries its own nonce rather than
// binding to the hello random — returns false → the caller proxies it to dest, so a replayer
// sees the real site rather than our termination).
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

// proxyToDest relays raw<->dest (prepending the buffered ClientHello) in a detached goroutine, bounded
// by the relay cap. A full relay pool must NOT close the connection on the spot: an instant FIN straight
// after the ClientHello is exactly the distinguisher Handle refuses to hand a censor. So a probe QUEUES
// for a slot, and the relays are bounded by an IDLE timeout so slots recycle instead of being pinned.
func (sv *Server) proxyToDest(raw net.Conn, hello []byte) {
	select {
	case sv.queue <- struct{}{}:
	default:
		raw.Close()
		return
	}
	go func() {
		// LEAVE THE WAITING ROOM ON ENTERING SERVICE. Holding the queue token for the goroutine's whole life
		// makes the queue inert: every relaying goroutine also holds one, so with both caps equal the queue is
		// full exactly when the relay pool is, and a new probe is CLOSED ON THE SPOT — the instant FIN this
		// exists to remove. The two semaphores only bound different things if a conn holds one at a time.
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
			sv.destUnreachable(err)
			raw.Close()
			return
		}
		// Both legs re-arm their deadline before every read and write, so this is an IDLE bound and never a
		// lifetime cap — a slow real download through the cover is untouched, while a silent connection
		// releases its slot instead of waiting on dest's keepalive to decide for us. It also supersedes the
		// handshake deadline Handle left on raw.
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

// idleConn re-arms its deadline before each operation. It embeds the net.Conn
// INTERFACE on purpose: that keeps ReadFrom/WriteTo off the wrapper, so io.Copy
// cannot splice past these methods and skip the deadlines.
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

// readClientHello reads exactly one TLS handshake record (the ClientHello),
// returns the raw bytes (for replay) plus the client random and session id.
func readClientHello(c net.Conn) (buf, sid []byte, err error) {
	// buf always holds every byte consumed from c, including on the error paths
	// below, so the caller can replay them verbatim to dest (a rejected hello must
	// still be proxied, never dropped).
	hdr := make([]byte, 5)
	n, err := io.ReadFull(c, hdr)
	buf = hdr[:n]
	if err != nil {
		return buf, nil, err
	}
	if hdr[0] != 0x16 { // TLS handshake content type
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
	// body: hs_type(1) hs_len(3) client_version(2) random(32) sid_len(1) sid...
	// (the 32-byte random at body[6:38] is no longer consumed — sealToken uses a fresh per-seal nonce.)
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

// prefixConn replays pre before delegating reads to the wrapped conn.
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

// SelfSignedCert makes a throwaway ECDSA certificate for host. Only our own
// client (which does not verify) ever sees it; probes get the real dest's cert.
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
