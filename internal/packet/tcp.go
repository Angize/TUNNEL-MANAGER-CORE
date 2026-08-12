// This file implements the core carrier over TCP. It mirrors udp.go (same type frame and Sealer
// contract) but adapts to a byte stream.
//
// Legacy framing (obfs off) — length-prefixed so the reader can reframe:
//
//	[0:2] uint16 big-endian N = length of the frame that follows (magic+type+payload)
//	[2]   magic = 0xB1
//	[3]   type  = 0 data | 1 ping | 2 pong
//	[4:]  payload — sealed(nonce||ct) for EVERY type when crypto is on (ping/pong seal an empty
//	      payload); the raw IP packet for data, empty for ping/pong, when crypto is off
//
// Obfs framing (obfs on) — no constant bytes on the wire:
//
//	handshake: each side writes a 24-byte random salt, then reads the peer's.
//	per frame: [0:2] uint16 length XOR ChaCha20-keystream(PSK,salt)
//	           [2:]  AEAD-sealed [type][realLen][payload][random-pad]
//
// The server holds up to maxAuthConns authenticated connections at once (a reconnecting client's
// previous one is still registered until it times out); one TUN reader feeds whichever one is live via
// an atomic pointer.
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
	maxFrame = 65535 // uint16 length prefix ceiling (payload fits far under this)

	// readBufSize is the bufio read buffer allocated per connection. It is kept
	// small (not maxFrame+2) so an unauthenticated peer cannot force a ~64 KB
	// eager allocation just by connecting; bufio reads larger frames directly
	// into the destination, so this does not cap frame size.
	readBufSize = 4096

	// handshakeTimeout bounds how long an UNAUTHENTICATED peer may hold a server
	// goroutine before its first frame authenticates — far shorter than the
	// established-connection idle deadline, to blunt slowloris/half-open floods.
	handshakeTimeout = 10 * time.Second

	// connectTimeout bounds ONE TCP connect to an endpoint. It is only ever spent on something that is
	// not answering: a live CDN edge completes the connect in ~115ms, measured three times each against
	// three of them from a clean host, so ten seconds was eighty-odd times the real cost and every one of
	// those seconds was a dead pin or a dead endpoint the pool could already have moved off.
	//
	// Four seconds still covers a lossy path: Linux re-sends the SYN at t=0, 1 and 3, so this budget
	// tolerates TWO lost SYNs before giving up. And it is what puts a cannot-land pin inside ten seconds
	// end to end -- two attempts plus the reconnect backoff between them.
	connectTimeout = 4 * time.Second

	// writeTimeout caps a single frame write so a peer advertising a zero receive
	// window cannot block the sole TUN reader (tunLoop) indefinitely.
	writeTimeout = 30 * time.Second

	// maxPreAuthConns bounds concurrent not-yet-authenticated server handlers, so
	// a connection flood cannot exhaust goroutines/fds/memory before auth.
	maxPreAuthConns = 128

	// pingLossThreshold (consecutive unanswered keepalives before a client closes), probeTimeout (edge
	// probe budget) and minLiveness (shortest healthy session) are operator-tunable package vars now,
	// defined with their defaults in tuning.go.

	// maxAuthConns bounds concurrent AUTHENTICATED server connections. A new connection never evicts the
	// previous one -- a client that re-dials is registered again while the old conn waits out its read
	// deadline -- and over the cap the oldest idle one is reaped. 3 leaves headroom for that overlap.
	maxAuthConns = 3
)

var (
	errDesync      = errors.New("core/tcp: stream desync")
	errPingTimeout = errors.New("core/tcp: keepalive pings unanswered")
	// errFrameTooBig means a single packet does not fit the frame's uint16 length ceiling — a property
	// of THIS packet (e.g. a GSO-coalesced super-packet larger than the TUN MTU), not a dead carrier.
	// The carrier stays up and the packet is dropped, so the same packet can't poison the tunnel by
	// re-closing it on every reconnect.
	errFrameTooBig = errors.New("core/tcp: frame exceeds max size")
)

// connFramer wraps a stream connection and owns the seal<->frame transform in
// both directions. A write lock lets the TUN reader and the keepalive loop emit
// frames without interleaving bytes (and, in obfs mode, without racing the
// stateful length keystream).
type connFramer struct {
	conn   net.Conn
	r      *bufio.Reader
	mu     sync.Mutex
	sealer Sealer
	obfs   bool
	psk    string

	// obfs length-prefix keystreams (nil until established). writeKS is keyed by
	// the salt we sent, readKS by the salt the peer sent (read lazily on the
	// first frame). saltSent guards the one-time salt emission.
	writeKS  *chacha20.Cipher
	readKS   *chacha20.Cipher
	saltSent bool
	// saltPend holds the salt after sendSalt prepared it and before a frame has carried it. A write of
	// its own is a fixed-size record right after the handshake, in both directions, bypassing obfsSeal's
	// padding — so it rides the SAME write as the next frame instead. Guarded by mu.
	saltPend []byte

	// rp is this connection's inbound anti-replay window. It is PER-CONNECTION, so two briefly
	// overlapping connections cannot flip-flop a shared window's session id. One connection carries one
	// peer session and is read by exactly one goroutine, so the lock-free replayGuard is safe here.
	rp replayGuard

	// unanswered counts CLIENT keepalive pings sent with no inbound frame in between.
	// keepaliveLoop bumps it per ping and drops the connection once it hits
	// pingLossThreshold; serve() resets it to 0 on any received frame. Touched by the
	// keepalive goroutine and the read goroutine, so it is atomic.
	unanswered atomic.Int32

	// rxAt is the unix-nano of the last authenticated inbound frame ON THIS CONNECTION — its own
	// liveness, kept per connection because the server holds several at once. The crypto
	// handshake seeds it (the responder answering is inbound proof a CDN edge cannot fake) and readLoop
	// advances it; adoptRx publishes it as the tunnel's b.lastRx when this carrier goes live.
	rxAt atomic.Int64
}

// sendSalt prepares our per-connection salt once and arms the write keystream. The server calls it only
// AFTER it has authenticated the client's first frame, so a peer that does not know the PSK gets zero
// bytes back. It does NOT write: the salt is queued in saltPend and leaves in the same conn.Write as the
// next frame, with flushSalt as the backstop for any path that sends none.
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

// flushSalt writes the salt on its own if nothing has carried it yet, and is a no-op otherwise. It is
// the correctness backstop for sendSalt's deferral: the peer's ensureReadKS blocks on the salt before
// it can read any frame, so the salt must never be able to sit in saltPend indefinitely. On every
// path we have today a frame follows immediately and this writes nothing.
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

// ensureReadKS reads the peer's salt (once) and arms the read keystream.
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

// writeFrame seals payload and writes one framed message.
func (cf *connFramer) writeFrame(typ byte, payload []byte) error {
	if cf.obfs {
		sealed, err := obfsSeal(cf.sealer, typ, payload, padMaxFor(typ))
		if err != nil {
			return err
		}
		if len(sealed) > maxFrame {
			return errFrameTooBig
		}
		out := make([]byte, 2+len(sealed))
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(sealed)))
		copy(out[2:], sealed)
		cf.mu.Lock()
		cf.writeKS.XORKeyStream(out[0:2], lb[:]) // mask length; advances keystream
		if len(cf.saltPend) > 0 {
			// First frame on this connection: the salt leaves in this same write, so obfs never emits
			// a bare constant-size record. append allocates (saltPend has no spare capacity), so out
			// and saltPend never alias.
			out = append(cf.saltPend, out...)
			cf.saltPend = nil
		}
		cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err = cf.conn.Write(out)
		cf.mu.Unlock()
		return err
	}

	// Legacy: [len][magic][type][sealed]. With crypto on we seal EVERY type
	// (ping/pong seal an empty payload) so control frames are authenticated.
	sealed := payload
	if cf.sealer != nil {
		s, err := cf.sealer.Seal(payload, []byte{typ}) // authenticate the type byte
		if err != nil {
			return err
		}
		sealed = s
	}
	n := 2 + len(sealed)
	if n > maxFrame {
		return errFrameTooBig
	}
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out[0:2], uint16(n))
	out[2] = magic
	out[3] = typ
	copy(out[4:], sealed)
	cf.mu.Lock()
	cf.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := cf.conn.Write(out)
	cf.mu.Unlock()
	return err
}

// readFrame reads one framed message and returns its type, the sender's
// (session, seq) for anti-replay, and the real payload (padding stripped, data
// unsealed). ping/pong carry a nil/empty payload. session/seq are 0 in clear
// mode (no crypto), where replay cannot be detected.
func (cf *connFramer) readFrame() (typ byte, session uint64, seq uint64, payload []byte, err error) {
	if cf.obfs {
		if err := cf.ensureReadKS(); err != nil { // peer salt precedes its frames
			return 0, 0, 0, nil, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(cf.r, hdr[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	if cf.obfs {
		var lb [2]byte
		cf.readKS.XORKeyStream(lb[:], hdr[:]) // unmask length; advances keystream
		n := int(binary.BigEndian.Uint16(lb[:]))
		// Only the FLOOR is a real check. The ceiling is structural: n came from a uint16, and maxFrame
		// IS the uint16 ceiling, so `n > maxFrame` could never be true — it only read as if a bound were
		// being enforced here. (The plain path below floors at 2 and asserts no ceiling either; the write
		// path's `n > maxFrame` stays, because there n is an int that really can overflow the prefix.)
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
	if cf.sealer != nil { // crypto on: every type is sealed and authenticated
		session, seq, payload, err = cf.sealer.Open(buf[2:n], []byte{typ}) // type-flip -> open fails
		if err != nil {
			return 0, 0, 0, nil, err
		}
		return typ, session, seq, payload, nil
	}
	if typ == typeData { // clear mode: only data carries a payload
		return typ, 0, 0, buf[2:n], nil
	}
	return typ, 0, 0, nil, nil
}

// TCP carries L3 packets between a TUN device and a TCP peer.
type TCP struct {
	dev       *tun.Device
	cryptoOn  bool
	cipher    string
	keepalive time.Duration
	obfs      bool
	psk       string
	idle      time.Duration // read deadline; reaps dead/probe connections

	cover     bool             // wrap the connection in a REALITY-style TLS cover
	coverSNI  string           // client: SNI to present; server: real dest to borrow
	coverHint sync.Once        // client: one line naming the two causes of a cover handshake that "succeeds" into the real site
	coverSrv  *tlscover.Server // server-side REALITY responder (nil on the client)

	// WebSocket carrier (transport "ws"): the stream is wrapped in RFC 6455 binary frames after an HTTP
	// Upgrade, so it can be fronted through a CDN. Mutually exclusive with cover. The client wraps the
	// connection in TLS (ServerName=wsHost) before the upgrade; the server stays plain (the CDN terminates).
	ws     bool
	wsHost string // client: Host header + TLS SNI (the fronting/origin domain)
	wsPath string // client: the request path to ask for; ws server: the ONLY path it answers 101 on (default "/")
	wsTLS  bool   // client: TLS to the edge before the WebSocket upgrade
	wsECH  []byte // client: ECHConfigList — when set, the SNI is encrypted (hidden)

	pool   *wsPool       // client: rotating edge pool (nil = single fixed edge above)
	rotate time.Duration // client: proactive pool-rotation interval (0 = failover-only)
	st     *coreStatus   // client + single-edge ws/http: self-heal event ring -> status file (nil = off / pool / server)
	stTag  string        // carrier label prefix ("tcp"/"cover"/"ws"/"http") for setActive on a direct-pool rotation; set alongside st
	lastRx atomic.Int64  // client: unix-nano of the last authenticated INBOUND frame on the LIVE carrier (status-file heartbeat)

	// lastRxData is the unix-nano of the last real DATA frame that ARRIVED (never ping/pong, and never
	// anything we sent) — it lets an active tunnel skip the standalone keepalive. INBOUND ONLY: stamping it
	// on an outbound write suppresses the ping forever and hides a receive-direction blackhole, because the
	// inner TCP retransmits and outbound data never stops. Stamped by handleFrame's typeData case only.
	lastRxData atomic.Int64

	// warmNext holds a connection that was fully dialled and handshaked BEFORE the live one was
	// dropped, so a timed destination rotation costs no outage: dialLoop adopts it instead of dialing.
	// Buffered depth 1 — only the rotation timer fills it, and only while a connection is live.
	// Drained on dialLoop exit so a conn built as Close fired cannot leak its fd.
	warmNext chan *warmDial

	// pp is the DESTINATION rotation pool for the direct TCP carriers (plain tcp / tcp+cover): the client
	// cycles the peer IPs and burns a blocked one, so a single filtered server IP does not kill the tunnel.
	// Only ever set on a non-ws client (the ws path has its own edge pool). nil = the fixed peer b.addr.
	// Unlike the datagram carriers' atomic peer swap, TCP rotates by re-dialing.
	pp *PeerPool
	// sp is the SOURCE rotation pool: the local IP the client dials FROM. TCP applies it via the
	// dialer's LocalAddr, so a rotation is picked up on the next re-dial (sourceIP reads sp.current()).
	// nil = fixed bindIP. Direct-tcp client only.
	sp *PeerPool

	sniSplit bool   // client ws/http: split the ClientHello so the cleartext SNI crosses a TCP segment boundary
	splitPos int    // explicit split offset into the ClientHello (0 = auto: middle of the hostname)
	sniMode  string // "split" (in-order) | "disorder" (low-TTL head, desyncs a reassembling DPI)
	splitTTL int    // disorder head-segment TTL (0 = default)

	// probeFn lets tests substitute a deterministic reachability oracle for the real network probe.
	// nil in production -> probe() uses probeEdgeFull (a full ws-upgrade / httpc-grpc
	// establish, so a CDN that terminates TLS for a dead origin isn't read as reachable).
	probeFn func(ip string, sni wsSNIEntry) bool

	// manualSwitch marks the NEXT carrier drop as operator-initiated (a pin / manual rotate via
	// rotate1), so the dial loop does not record it as a data-plane fault and re-dials from current(),
	// which honours the just-set edge.
	manualSwitch atomic.Bool

	// lastErr holds the most recent CAUSE of a client carrier death (as a string), so the pool can
	// record a precise "down" reason for the panel log instead of a guess. "use of closed network
	// connection" is a consequence (we closed it) and is deliberately never stored.
	lastErr atomic.Value // string

	// HTTP carrier (transport "ws" with ws_httpc): the stream rides an HTTP request pair (post: GET-down +
	// seq-POSTs-up) or one full-duplex request (stream-one) instead of a WebSocket upgrade, so it passes a
	// CDN that blocks WebSocket. The same fronting fields apply, but the server must NOT run
	// wsServerHandshake on such a conn — see handleServerConn.
	httpc         bool
	httpcMode     string                      // client: "grpc" (single full-duplex request) else "post"
	httpcTLS      *tls.Config                 // test-only: overrides the client edge TLS config (nil in production)
	httpSrv       atomic.Pointer[http.Server] // server: the HTTP-carrier endpoint (nil otherwise); atomic — written by runHTTPCServer's goroutine, read by Close
	httpcMu       sync.Mutex
	httpcSessions map[string]*httpcSession

	isClient bool
	addr     string // server: listen addr; client: peer addr
	bindIP   string // client: source IP to dial FROM (empty = kernel default); tcp/ws/http only
	// destRot counts destination burns since the last healthy session, so the SOURCE pool is only walked
	// once the destination pool has cycled through every endpoint against it. Written by the dial loop and
	// by the rotation timer (which reaches burnAdvance through buildWarm), hence atomic.
	destRot  atomic.Int64
	destWant atomic.Int64 // ...and how many that round set out to try, snapshotted before the first burn
	// pinFails counts consecutive proven-dead rounds while an operator pin is in force, so a pin costs
	// a SECOND OPINION to break rather than being either absolute or worth one measurement. One field
	// for both pools: a carrier has direct endpoints or a CDN edge pool, never both.
	pinFails  atomic.Int64
	destTick  atomic.Int32 // timed-rotation beats since the source last moved (the odometer's low digit)
	sniRot    atomic.Int64 // ws edge pool: SNI burns on this edge since the last healthy session
	sniWant   atomic.Int64 // ...and how many that round set out to try, snapshotted before the first burn
	srcWarned sync.Map     // sources already reported as unbindable (one log line per source)
	probing   atomic.Bool  // a retest batch is in flight; keeps the retest tick free for the operator pin
	// lastSrc is the source the dialer really BOUND to — empty when no bind was applied (none
	// configured, or the IP is not on this host). Releasing a source pin is conditioned on it, so a
	// pin is never consumed by a connection that leaves from somewhere else. Written in dialer(),
	// read at the pin-release site.
	lastSrc atomic.Pointer[string]

	// TCP-segment injection desync (client, optional): after each kernel TCP connect, sendTCPFakes injects
	// `count` low-TTL decoy segments on the real 4-tuple to mis-sync a stateful DPI, leaving the
	// kernel-owned connection untouched. Primitive fields (not the linux-only desyncCfg) so this compiles
	// everywhere; best-effort, since it needs CAP_NET_RAW.
	dsOn       bool
	dsTTL      int
	dsCount    int
	dsMode     string
	dsFailOnce sync.Once  // logs an AF_PACKET/capability failure at most once (fired per connect)
	dsSend     desyncSend // outcome of the decoy TRANSMITS — opening the injector succeeding says nothing about them
	// dsWatch is a TEST SEAM, nil in production: sendTCPFakes calls it with the conn it is about to mirror,
	// before the dsOn gate, so a test can assert WHEN the decoys go out relative to the cover/WebSocket
	// handshake — not observable from the byte stream, since they leave through AF_PACKET.
	dsWatch func(net.Conn)

	ln      net.Listener               // server: primary/first listener (ws/http use only this)
	lns     []net.Listener             // server: ALL bound listeners; a pooled direct-TCP server binds one per selected IP so it accepts on exactly the IPs the client rotates through (lns[0]==ln)
	cur     atomic.Pointer[connFramer] // currently live connection / server downstream target (nil when none)
	curConn atomic.Pointer[net.Conn]   // client+pool: the live carrier conn, closed to force a re-dial on rotation
	closed  atomic.Bool
	closeCh chan struct{}
	preAuth chan struct{} // permits: caps concurrent unauthenticated handlers

	// authConns tracks the server's AUTHENTICATED connections (oldest first) so a client that re-dials
	// does not have its previous conn evicted by the newest. Bounded by maxAuthConns; over the cap the
	// oldest non-downstream conn is reaped. Server-side only.
	authMu    sync.Mutex
	authConns []*connFramer
}

// SetSourceIP pins the client's outbound dials to a specific source IP (the node's own
// registered IP), so on a multi-IP host the peer/CDN sees that IP instead of the kernel's
// default primary. No effect on the server side or on raw/flux carriers. Call before Run.
func (b *TCP) SetSourceIP(ip string) { b.bindIP = ip }

// SetPeerPool (client, direct tcp/cover only) wires a destination rotation pool: the client dials the
// pool's current endpoint, burns one that won't connect (or dies immediately), and a proactive timer
// also rotates. The ws path has its own edge pool, so this is refused there. nil / single-endpoint =
// no rotation. main wires it via the shared SetPeerPool type assertion. Call before Run().
func (b *TCP) SetPeerPool(pp *PeerPool) {
	if b.isClient && !b.ws {
		b.pp = pp
	}
}

// dialTarget is the address the next dial should use: the rotation pool's current endpoint when a
// pool is wired, otherwise the fixed peer. b.addr is never mutated (the pool holds the moving state,
// like the ws pool), so this is safe to read from the dial goroutine while a timer rotates the pool.
func (b *TCP) dialTarget() string {
	if b.pp != nil {
		return b.pp.current()
	}
	return b.addr
}

// directPinInForce reports whether an operator pin is live on either DIRECT pool. The ws edge pool
// keeps its own pin state, and burnAdvanceWS guards it.
func (b *TCP) directPinInForce() bool {
	return (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned())
}

// lastSourceUsed returns the source the dialer most recently BOUND to (the raw pool entry, so it
// compares directly against a pin key), so releasing a source pin can be conditioned on where the
// connection actually leaves from rather than on the pool's state at some later moment. Empty when
// the last dial applied no bind at all — none was configured, or the IP was not on this host.
func (b *TCP) lastSourceUsed() string {
	if s := b.lastSrc.Load(); s != nil {
		return *s
	}
	return ""
}

// SetSourcePool (client, direct tcp/cover only) wires a source-IP rotation pool: the local IP the
// client dials FROM is cycled/burned alongside the destination. Refused on the ws path (its edge pool
// owns rotation). nil / single-endpoint = the fixed bindIP. Call before Run().
func (b *TCP) SetSourcePool(sp *PeerPool) {
	if b.isClient && !b.ws {
		b.sp = sp
	}
}

// sourceIP is the local IP the next dial binds to: the source pool's current entry when wired, else
// the fixed bindIP. Like dialTarget, b.bindIP is never mutated — the pool holds the moving state — so
// this is safe to read from the dial goroutine while a timer rotates the pool.
func (b *TCP) sourceIP() string {
	if b.sp != nil {
		return b.sp.current()
	}
	return b.bindIP
}

// endRound clears the bookkeeping ONE outage owns: the lap each pool is walking and the allowance an
// operator pin has left. Both are counts of CONSECUTIVE proven-dead rounds, so a carrier that came up
// healthy ends the run — this is rotationController.success, for the two carriers that reach their
// odometer through this file instead of through that controller.
func (b *TCP) endRound() {
	b.destRot.Store(0)
	b.sniRot.Store(0)
	b.pinFails.Store(0)
}

// pinFailedOn reports one failed attempt against (ip, host) to whichever pool this carrier has, so an
// operator pin that cannot land is released on the core's OWN evidence rather than waiting for the
// node's tunnel verdict. nil-safe on both.
func (b *TCP) pinFailedOn(ip, host string) {
	if b.pool != nil {
		b.pool.pinAttemptFailed(ip, host)
	}
	if b.pp != nil {
		b.pp.pinAttemptFailed(ip)
	}
}

// burnAdvance burns+advances the destination pool and, once that pool has cycled through every endpoint
// against the current source, walks the SOURCE too. Returns the endpoint the pool now points at, and
// PUBLISHES NOTHING — the caller owns every event, because make-before-break burns an endpoint the live
// carrier never went to. carrierGone=false (a failed warm build) advances without burning or announcing.
func (b *TCP) burnAdvance(carrierGone bool) (string, bool) {
	// An operator pin is a PREFERENCE, not a hostage-taking: it holds off failover, but only until the
	// probe has said the same thing pinFailRelease times. Freezing outright left a tunnel pinned to a
	// blocked endpoint down indefinitely while udp/raw/flux recovered from the identical
	// evidence — this is that same second opinion, on the same counter.
	if (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned()) {
		if n := b.pinFails.Add(1); int(n) < pinFailRelease {
			return "", false
		}
		b.pinFails.Store(0)
		if b.pp != nil {
			b.pp.releasePin()
		}
		if b.sp != nil {
			b.sp.releasePin()
		}
		// pins cleared — fall through and burn+advance off the blocked endpoint this round
	} else {
		b.pinFails.Store(0) // not pinned -> a later pin starts its release count fresh
	}
	walkSource := func() { b.rotateSourceTCP(!carrierGone) }
	if b.pp == nil {
		if b.sp != nil {
			walkSource()
		}
		return "", false
	}
	// ELIGIBLE, not size, and sized ONCE at the start of the round — see rotationController.fail, which
	// snapshots it the same way. A condemned destination cannot be tried, so counting the raw list blames
	// the source for a lap that never happened; and re-reading the ELIGIBLE count on every ask is the
	// same bug one step in: each burn shrinks the number the next ask compares against, so three
	// destinations declare a lap after two. Floored at one: with nothing eligible, the endpoint we are
	// on IS the experiment.
	want := int(b.destWant.Load())
	if b.destRot.Load() == 0 {
		want = b.pp.eligibleCount()
		b.destWant.Store(int64(want))
	}
	if want < 1 {
		want = 1
	}
	addr, _ := b.pp.fail()
	if n := b.destRot.Add(1); b.sp != nil && int(n) >= want {
		walkSource()
		b.destRot.Store(0)
	}
	return addr, true
}

// rotateSourceTCP advances the source pool so the NEXT dial binds to a new local IP, returning the new
// source and whether it actually moved. It performs no teardown — the caller drives the re-dial that
// picks up sourceIP(). A FAILOVER (proactive=false) publishes the src-rotate event here; the PROACTIVE
// timer publishes nothing and carries the address to the adoption site, where the move becomes real.
func (b *TCP) rotateSourceTCP(proactive bool) (addr string, moved bool) {
	if b.sp == nil {
		return "", false
	}
	addr, moved = b.sp.nextEndpoint(proactive)
	if moved {
		log.Printf("core/tcp: rotated source to %s", addr)
		if !proactive {
			// A failover source rotation keeps the session (no reconnect to pair), so it is a plain
			// event() not a down(). nil-safe: a no-op on a ws edge pool (b.st==nil there) or the server.
			b.st.event("down", "src-rotate", "ip:"+addr)
		}
	}
	return addr, moved
}

// SetDesync (client, optional) turns on TCP-segment injection desync for the tcp/cover/ws carriers:
// after each connect, sendTCPFakes injects `count` decoy segments on the real 4-tuple to mis-sync a
// stateful DPI. Stores the config; the injection itself is Linux-only. No-op on the server. Call
// before Run().
func (b *TCP) SetDesync(on bool, ttl, count int, mode string) {
	if !b.isClient || !on {
		return
	}
	// Say the cap out loud here, at the one place that knows it applies: every decoy on THIS carrier rides
	// the real connection's 4-tuple, so specsTCP clamps the TTL to injectMaxTTL while config, node and
	// panel all still report the operator's number.
	if ttl > injectMaxTTL {
		log.Printf("core/tcp: fake_ttl=%d is capped to %d on this carrier — its decoys ride the real connection's 4-tuple, so one that reached the server would draw an RST", ttl, injectMaxTTL)
	}
	b.dsOn, b.dsTTL, b.dsCount, b.dsMode = true, ttl, count, mode
}

// SetSNISplit (client, ws/http) turns on SNI fragmentation: the TLS ClientHello to the edge is written
// across two TCP segments so the cleartext SNI is split, defeating a stateless SNI-blocklist DPI. pos is
// the split offset (0 = auto: the middle of the hostname). It REPORTS whether it took — the knob means
// nothing on a carrier that never sends a ClientHello, and the caller logs off this answer.
func (b *TCP) SetSNISplit(on bool, pos int, mode string, ttl int) bool {
	if !b.isClient || !on || !b.ws {
		return false
	}
	b.sniSplit, b.splitPos, b.sniMode, b.splitTTL = true, pos, mode, ttl
	return true
}

// fragWrap wraps conn in a ClientHello-splitting fragConn when SNI fragmentation is enabled, else
// returns conn unchanged. host is the SNI, used for auto split-point location; ech is the ECHConfigList
// this dial will present (empty = no ECH), which the conn needs only so its fallback messages can name
// the real reason the hostname was not in the ClientHello instead of assuming ECH.
func (b *TCP) fragWrap(conn net.Conn, host string, ech []byte) net.Conn {
	if b.sniSplit {
		return newFragConn(conn, host, b.splitPos, b.sniMode, b.splitTTL, len(ech) > 0, &b.dsSend)
	}
	return conn
}

// SetStatusPath (client, single-edge ws/http) wires a status-file event ring so the carrier's self-heal
// events reach the node/panel system log, in the same file shape the datagram carriers write. Skipped
// when a pool is configured (it writes its own richer status file) and on the server. Call before Run().
func (b *TCP) SetStatusPath(path string) {
	if path == "" || b.pool != nil {
		return
	}
	// Label the status file by the ACTUAL transport, not a hardcoded "ws": a direct tcp or a
	// cover/REALITY carrier also reaches here and must not be mislabeled "ws". httpc implies ws,
	// so it is checked first; cover is a direct-tcp variant, so it falls under the non-ws branch.
	carrier := "tcp"
	switch {
	case b.httpc:
		carrier = "http"
	case b.ws:
		carrier = "ws"
	case b.cover:
		carrier = "cover"
	}
	b.st = newCoreStatus(path, carrier+" · "+b.addr)
	b.stTag = carrier // reused by setActive when a direct dest pool rotates the active endpoint
}

// dialer returns a net.Dialer that, when a source IP is pinned, binds the outbound socket to it
// (LocalAddr). Only an IP that is actually configured on this host is bound: a well-formed address no
// longer on any interface fails every dial with EADDRNOTAVAIL, and dialLoop charges a failed dial to the
// DESTINATION — so one bad source would burn the whole destination pool while the peers are reachable.
func (b *TCP) dialer(timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	src := b.sourceIP() // rotation pool's current source, or the fixed bindIP
	// lastSrc records what the socket will really leave from, so it is set ONLY on the branch that
	// installs LocalAddr: a silently dropped source reported as bound also releases the source pin
	// against a dial that actually left from the kernel's default IP.
	unbound := ""
	b.lastSrc.Store(&unbound)
	if src != "" {
		// Tolerate an accidental "ip:port", as config.go's validatePoolEndpoint promises and as udp
		// (rebindSourceTo) and raw/flux (hostOnly) already do: ParseIP("10.0.0.5:0") is nil, and everything
		// below sits inside `if ip != nil`.
		host := src
		if h, _, e := net.SplitHostPort(src); e == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil && canBindSource(ip) {
			d.LocalAddr = &net.TCPAddr{IP: ip}
			b.lastSrc.Store(&src) // the raw pool entry, so it compares directly against a pin key
		} else {
			b.dropUnusableSource(src, host, ip != nil)
		}
	}
	return d
}

// dropUnusableSource handles a configured source the socket cannot actually leave from: the IP is no
// longer on any interface, or the string is not an IP at all. The dial still goes out on the kernel
// default rather than failing, because dialLoop charges a failed dial to the DESTINATION. The entry is
// burned too, so rotation walks onto a source that works; a pinned one is left alone and lapses on TTL.
func (b *TCP) dropUnusableSource(src, host string, parsed bool) {
	if _, dup := b.srcWarned.LoadOrStore(src, struct{}{}); !dup {
		if parsed {
			log.Printf("core/tcp: source IP %s is not configured on this host — dialing from the kernel default instead", host)
		} else {
			log.Printf("core/tcp: source %q is not a usable IP address — dialing from the kernel default instead", src)
		}
	}
	if b.sp == nil {
		return
	}
	// An operator jump aimed HERE is over: this IP has just proven it cannot be used, and a jump is a
	// momentary move within the rotation, not a lock. Ending it now also unblocks the burn below —
	// fail() refuses to touch a pinned entry.
	if b.sp.pinCannotLand(src) {
		log.Printf("core/tcp: manual jump to source %s abandoned — that IP is not configured on this host", src)
	}
	// failUnusable, not fail: the kernel refused this address, which is not the remote-reachability
	// question auto-burn is a policy for. See PeerPool.failUnusable.
	b.sp.failUnusable() // pull it from rotation so the NEXT dial gets a source that can actually bind
}

// canBindSource reports whether the kernel will let us bind an outbound socket to ip. It ASKS the kernel
// rather than comparing against InterfaceAddrs(): loopback aliases are bindable while the interface
// reports only 127.0.0.1/8, and a subnet-contains test would accept the peer's own address. A throwaway
// bind on port 0 is the same question the dial asks, and it is not on the data path.
func canBindSource(ip net.IP) bool {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip, Port: 0})
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// deadWindow is how long a carrier tolerates silence before it calls the link dead: deadMult×keepalive,
// the ONE rule for every carrier and both roles. On tcp/ws it becomes the connection's read deadline; on
// the datagram carriers it is the session-stale window. Keepalive is therefore the single number that
// sizes self-heal speed.
func deadWindow(keepalive time.Duration) time.Duration {
	return time.Duration(deadMult) * keepalive
}

// DialTCP (client role) targets peerAddr and reconnects on drop. When cover is
// set the connection is wrapped in a Chrome-fingerprinted TLS session presenting
// coverSNI, so it looks like HTTPS on the wire.
func DialTCP(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: deadWindow(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// DialWS (client role) is DialTCP over a WebSocket carrier: it dials peerAddr (a
// CDN edge or the origin), optionally wraps it in TLS (wsTLS, ServerName=wsHost),
// then performs the WebSocket upgrade with Host=wsHost before the core framing runs.
func DialWS(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: deadWindow(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// DialWSPool is DialWS over a rotating edge POOL: the client cycles (edge-IP × SNI) combinations, each
// SNI with its own ECH, moving before any single edge is fingerprinted and burning a blocked one.
// rotate is the proactive interval (0 = failover only).
func DialWSPool(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, pool *wsPool, rotate time.Duration, httpc bool, httpcMode string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsTLS: true, httpc: httpc, httpcMode: httpcMode, pool: pool, rotate: rotate,
		idle: deadWindow(keepalive), isClient: true, addr: "pool", closeCh: make(chan struct{})}, nil
}

// newWSPoolFromCfg builds a pool from the config's clean IP/SNI lists (decoding each
// SNI's base64 ECH), or returns nil when no pool is configured.
func newWSPoolFromCfg(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	if len(ips) == 0 || len(snis) == 0 {
		return nil
	}
	return newWSPool(ips, snis, autoBurn, statusPath)
}

// DialHTTPC (client role) is DialWS over the HTTP carrier: it reaches the edge with the
// same wss/ECH/Host, but carries the stream over a GET(down)+POST(up) pair rather than a
// WebSocket upgrade, so it passes a CDN that blocks WebSocket.
func DialHTTPC(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher, wsHost, wsPath string, wsTLS bool, wsECH []byte, httpcMode string) (*TCP, error) {
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, httpc: true, httpcMode: httpcMode, wsHost: wsHost, wsPath: wsPath, wsTLS: wsTLS, wsECH: wsECH,
		idle: deadWindow(keepalive), isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// ListenHTTPC (server role) serves the HTTP-carrier endpoint over plain HTTP (a CDN in front
// terminates TLS). A non-session request gets a plausible 404.
func ListenHTTPC(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, httpc: true, idle: deadWindow(keepalive), addr: listenAddr, ln: ln, lns: []net.Listener{ln}, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns), httpcSessions: make(map[string]*httpcSession)}, nil
}

// ListenWS (server role) accepts WebSocket connections (plain HTTP upgrade; a CDN in front terminates
// TLS). Anything that is not a well-formed upgrade for wsPath gets a plausible 404 and is dropped, so
// the port looks like an ordinary web endpoint. wsPath is the operator's ws_path ("" means "/").
func ListenWS(listenAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher, wsPath string) (*TCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		ws: true, wsPath: wsPath, idle: deadWindow(keepalive), addr: listenAddr, ln: ln, lns: []net.Listener{ln}, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}, nil
}

// ListenTCP (server role) binds each addr in listenAddrs and accepts on all of them, so a server under a
// destination rotation pool accepts on exactly the IPs the client dials across. With cover set it builds
// a REALITY responder that authenticates our clients by a token in their ClientHello and transparently
// proxies every other connection to the real coverSNI:443, so active probing sees that site's cert.
func ListenTCP(listenAddrs []string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, cover bool, coverSNI string) (*TCP, error) {
	if len(listenAddrs) == 0 {
		return nil, errors.New("tcp listen: no listen address")
	}
	var lns []net.Listener
	for _, addr := range listenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range lns { // release the ones we already bound
				l.Close()
			}
			return nil, err
		}
		lns = append(lns, ln)
	}
	b := &TCP{dev: dev, cryptoOn: cryptoOn, cipher: cipher, keepalive: keepalive, obfs: obfs, psk: psk,
		cover: cover, coverSNI: coverSNI,
		idle: deadWindow(keepalive), addr: listenAddrs[0], ln: lns[0], lns: lns, closeCh: make(chan struct{}),
		preAuth: make(chan struct{}, maxPreAuthConns)}
	if cover {
		// coverSNI is required (validated in config); it is the real site the
		// server borrows and proxies non-authenticated connections to.
		cs, err := tlscover.NewServer(psk, coverSNI)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return nil, err
		}
		// A cover site this server cannot reach makes the cover a lie: every probe gets a bare close where
		// the real site would have answered. Say so at startup instead of never — on an Iran-side server an
		// unreachable foreign cover domain is the normal case.
		cs.WarnIfDestUnreachable()
		b.coverSrv = cs
	}
	return b, nil
}

// Run blocks until Close is called. The TUN reader runs for the whole lifetime;
// the connection side either accepts (server) or dials-with-retry (client).
func (b *TCP) Run() error {
	// The TUN reader's death must REACH here. Fire-and-forget lets keepaliveLoop go on pinging and the
	// pongs go on advancing b.lastRx while not one byte can move — the panel reads GREEN on a dead
	// tunnel. Buffered so neither sender can block once the other has won.
	errc := make(chan error, 2)
	go func() { errc <- b.tunLoop() }()
	if b.isClient {
		go b.keepaliveLoop()
		go b.diagLoop() // low-rate goroutine-count heartbeat so a slow session leak is visible in the log
		if b.pool != nil {
			go b.retestLoop() // background health retests with exponential backoff
		} else if b.pp != nil || b.sp != nil {
			go b.peerPinPollLoop() // direct pp/sp pools: apply operator pins from the node's cmd file
		}
		// Each of these blocks until Close, so it moves onto its own goroutine and reports through the
		// same channel — Run now returns for whichever reason comes first, the connection side ending
		// or the TUN reader dying, instead of only ever the former.
		go func() {
			b.dialLoop()
			errc <- nil // the dial loop only ends on Close
		}()
	} else if b.httpc {
		go func() { b.runHTTPCServer(); errc <- nil }()
	} else {
		// One accept loop per bound listener. A pooled direct-TCP server binds several of its own IPs
		// (one listener each). ws/cover bind a single listener → this is a 1-element loop.
		for i := 1; i < len(b.lns); i++ {
			go b.acceptLoopOn(b.lns[i])
		}
		go func() { b.acceptLoopOn(b.lns[0]); errc <- nil }()
	}
	return <-errc
}

// Close stops the carrier and unblocks Run.
func (b *TCP) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	close(b.closeCh)
	if s := b.httpSrv.Load(); s != nil {
		s.Close()
	}
	for _, l := range b.lns { // close every bound listener (a pooled server has several)
		l.Close()
	}
	if c := b.cur.Load(); c != nil {
		c.conn.Close()
	}
	return nil
}

// newFramer builds a connFramer with NO sealer yet. In clear mode it stays nil;
// in crypto mode the ephemeral handshake installs the session sealer before any
// framed data is read or written.
func (b *TCP) newFramer(conn net.Conn) *connFramer {
	return &connFramer{conn: conn, r: bufio.NewReaderSize(conn, readBufSize), obfs: b.obfs, psk: b.psk}
}

// clientHandshake (client) sends an init and reads the responder's reply, then
// installs the ephemeral session sealer. Runs under the caller's read deadline.
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

// serverHandshake (server) reads an init, authenticates it, installs the session
// sealer, and replies. A wrong PSK / probe fails ParseInit and gets no response.
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

// acceptLoop (server) hands each new connection to a per-connection goroutine.
// On a transient Accept error (e.g. EMFILE from an fd flood) it backs off briefly
// instead of busy-spinning the CPU and flooding the log.
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

// handleServerConn serves one accepted connection. Whenever crypto is on, the connection is
// authenticated BEFORE it is published as live: the first frame must AEAD-open and pass anti-replay, so
// an unauthenticated peer cannot evict the real client by simply connecting. In obfs mode the salt is
// withheld until then too. Only clear mode — no authentication by definition — publishes at once.
func (b *TCP) handleServerConn(conn net.Conn) {
	// Take a pre-auth permit; shed load if too many handshakes are already in
	// flight. The permit is released the moment the connection becomes live
	// (authenticated), so it only bounds the UNAUTHENTICATED window, never the
	// long-lived established connection.
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

	if b.ws && !b.httpc { // WebSocket upgrade; a non-WS probe gets a 404 and is dropped
		// (httpc is excluded: its conn already carries core frames — the HTTP GET/POST pair
		// or the single full-duplex request replaced the WS upgrade — so a ws handshake here
		// would misread the client's core handshake as an HTTP request and drop the session.)
		r, werr := wsServerHandshake(conn, b.wsPath, time.Now().Add(handshakeTimeout))
		if werr != nil {
			conn.Close()
			return
		}
		conn = &wsConn{Conn: conn, r: r, client: false}
	} else if b.cover { // REALITY cover: authenticate by ClientHello token, else proxy to dest
		tconn, err := b.coverSrv.Handle(conn, time.Now().Add(handshakeTimeout))
		if err != nil {
			// ErrProbe: the relay goroutine now owns conn (proxying it to the
			// real site) — must NOT close it here. Any other error is fatal.
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
	// crypto on: run the ephemeral handshake, then read+authenticate the first
	// framed message silently before publishing. A wrong PSK / probe fails the
	// handshake and is dropped in silence. A SHORT handshake deadline (not the
	// 60 s idle) bounds the pre-auth hold.
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if err := b.serverHandshake(cf); err != nil {
		conn.Close()
		return
	}
	typ, session, seq, payload, err := cf.readFrame()
	if err != nil || !cf.rp.ok(session, seq) {
		conn.Close() // probe / wrong PSK / replay: no reply, no log noise
		return
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil { // authenticated — now answer
			conn.Close()
			return
		}
	}
	log.Printf("core/tcp: peer connected from %s", conn.RemoteAddr())
	b.publishServerConn(cf)
	release() // authenticated: no longer occupies a pre-auth slot
	b.handleFrame(cf, typ, payload)
	if b.obfs {
		// No-op on every path we have: the frame above is the client's prime ping, so handleFrame's
		// pong already carried the salt. Here so a first frame that happens NOT to be answered can
		// never leave the client blocked in ensureReadKS. See flushSalt.
		_ = cf.flushSalt()
	}
	b.serve(cf)
}

// publishServerConn (server) registers a freshly-authenticated connection. It does NOT evict the
// previous one: a client re-dialling after a rotation is registered again while its old conn is still
// waiting out the read deadline, and evicting would tear down the tunnel the client is still on. It
// becomes the downstream target only when there is none yet (CAS on nil); from there downstream follows
// the connection the client last sent DATA on (see handleFrame).
func (b *TCP) publishServerConn(cf *connFramer) {
	b.cur.CompareAndSwap(nil, cf)
	b.authMu.Lock()
	b.authConns = append(b.authConns, cf)
	cur := b.cur.Load()
	var reap []*connFramer
	for len(b.authConns) > maxAuthConns {
		idx := -1
		for i, c := range b.authConns {
			if c != cur { // never reap the live downstream target
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
		// handleFrame may Store a reaped conn as b.cur without authMu after our
		// snapshot, making it the live downstream target between snapshot and close.
		// Re-check against the now-current conn: if it just became downstream, skip
		// the close and re-track it in authConns so it survives and is not leaked.
		if v == b.cur.Load() {
			b.authMu.Lock()
			b.authConns = append(b.authConns, v)
			b.authMu.Unlock()
			continue
		}
		v.conn.Close() // its serve loop errors out -> onConnErr cleans up cur/authConns
	}
}

// reelectDownstream (server) re-points the downstream at another AUTHENTICATED connection once the live
// one has died. publishServerConn claims only an EMPTY downstream and handleFrame moves it only on a
// DATA frame, so without this a one-way flow the client is merely receiving stays dark. CAS on nil so
// the client's own choice always wins; a stale pick self-corrects through the failed write's onConnErr.
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

// removeAuthConn drops a connection from the server's authenticated set (called from onConnErr).
// A no-op on the client, whose authConns is always empty.
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

// noteECHSelfHeal runs after a SUCCESSFUL in-band ECH self-heal on the LIVE carrier. It persists
// the fresh key so the next reconnect stops re-healing (no repeat rejection), and surfaces the
// event to the panel exactly once per rotation — via the edge pool (multi-edge) or, for a single
// fixed edge, the status file. A no-op emit when neither sink exists.
func (b *TCP) noteECHSelfHeal(host string, ech []byte) {
	detail := host + " " + base64.StdEncoding.EncodeToString(ech)
	if b.pool != nil {
		if b.pool.updateECH(host, ech) { // persist onto the matching SNI; emit only on a real change
			b.pool.event("ech", "self_heal", detail)
		}
		return
	}
	// Single edge: wsECH is touched only by the one dial-loop goroutine, so this needs no lock.
	// Persist the fresh key and emit once per actual change (the next connect presents it directly).
	if !bytes.Equal(b.wsECH, ech) {
		b.wsECH = ech
		b.st.event("ech", "self_heal", detail) // nil-safe: a no-op when no status file is wired
	}
}

// tlsToEdge performs the client-side TLS handshake to the CDN edge over an already-dialed conn, using
// uTLS with a Chrome fingerprint so the ClientHello is indistinguishable from a real browser's.
// ServerName=wsHost is the SNI, encrypted when wsECH is set; a stale-ECH rejection carries a fresh
// RetryConfigList, so we redial once with it. budget bounds every leg, and a failed conn is closed.
func (b *TCP) tlsToEdge(conn net.Conn, dialAddr, host string, ech []byte, live bool, budget time.Duration) (net.Conn, error) {
	var err error
	healed := false // set once we redial with a fresh RetryConfigList
	for attempt := 0; attempt < 2; attempt++ {
		var uc net.Conn
		// ALPN forced to http/1.1: the WebSocket upgrade that follows (wsClientHandshake) is
		// HTTP/1.1, so the edge must not pick h2.
		uc, err = uEdgeHandshake(b.fragWrap(conn, host, ech), host, ech, []string{"http/1.1"}, false, budget) // split the ClientHello's SNI when enabled
		if err == nil {
			if healed && live { // live self-heal: persist the fresh key and surface it (pool or single-edge)
				b.noteECHSelfHeal(host, ech)
			}
			return uc, nil
		}
		conn.Close()
		var echErr *utls.ECHRejectionError
		if attempt == 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			ech = echErr.RetryConfigList // stale ECH key: redial and retry with the fresh one
			log.Printf("core/ws: ECH-SELFHEAL[reactive/in-band] for %s (%s) — stale key rejected, retrying with fresh key %s",
				host, dialAddr, base64.StdEncoding.EncodeToString(ech))
			healed = true
			if conn, err = b.dialer(budget).Dial("tcp", dialAddr); err != nil {
				return nil, err
			}
			// A FRESH 4-tuple needs its own decoys: establishWS injected on the conn we closed five lines up, so
			// without this the connection handed back would get none. Every TCP connection this carrier dials
			// gets one pass, on the bare 4-tuple, before any of our own bytes flow.
			b.sendTCPFakes(conn)
			continue
		}
		break
	}
	return nil, err
}

// uEdgeHandshake performs one client-side uTLS handshake to a CDN edge, presenting a current-Chrome
// ClientHello so our JA3 matches a real browser's (ECH hides the SNI, not the fingerprint). With ech set
// uTLS carries the real Encrypted ClientHello instead of Chrome's GREASE-ECH; a stale key comes back as
// *utls.ECHRejectionError with fresh RetryConfigs. budget is a parameter — this arms the socket deadline.
func uEdgeHandshake(conn net.Conn, host string, ech []byte, alpn []string, goFingerprint bool, budget time.Duration) (net.Conn, error) {
	cfg := &utls.Config{ServerName: host}
	var echPub []string
	// echRejected records that the blanket-accept hook below actually fired, i.e. the edge rejected our
	// ECH and uTLS therefore SKIPPED certificate verification entirely. Written by the hook, which uTLS
	// calls synchronously on this goroutine inside Handshake — no other goroutine touches it.
	echRejected := false
	if len(ech) > 0 {
		cfg.EncryptedClientHelloConfigList = ech
		echPub = echPublicNames(ech) // the SNIs the edge may present a cert for when it REJECTS our ECH
		if len(echPub) > 0 {
			// Self-heal on an ECH REJECTION with a cert mismatch. When our key is stale the edge completes the
			// OUTER handshake against the ECH public-name cert, and uTLS's default reject path fails hostname
			// verification before it can surface the fresh RetryConfigList. Accept the outer cert at this hook so
			// uTLS proceeds and returns the key; the real authentication happens below, once the certs are readable.
			cfg.EncryptedClientHelloRejectionVerify = func(utls.ConnectionState) error {
				echRejected = true
				return nil
			}
		}
	}
	var uc *utls.UConn
	var err error
	if goFingerprint {
		// grpc mode. A browser cannot make a gRPC call, so a Chrome ClientHello under
		// Content-Type: application/grpc + TE: trailers is a combination that exists nowhere. Real gRPC
		// clients ride Go's crypto/tls, so Go's ClientHello is the fingerprint that MATCHES the grpc-go
		// User-Agent the request carries (see grpcUA); changing only one would just relocate the mismatch.
		cfg.NextProtos = alpn // HelloGolang takes ALPN from the config, not from a spec
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
		// On an ECH rejection uTLS hands back a fresh RetryConfigList after completing the outer handshake
		// against the public-name cert, which the hook above accepted unverified. Authenticate that cert NOW,
		// before the caller redials, so the self-heal never adopts attacker-supplied ECH configs — those would
		// let a MITM decrypt the redial's inner ClientHello and unmask the real SNI.
		var echErr *utls.ECHRejectionError
		if len(echPub) > 0 && errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
			if verr := verifyECHPublicName(uc.ConnectionState().PeerCertificates, echPub); verr != nil {
				return nil, fmt.Errorf("ech-reject: outer cert not valid for %v: %w", echPub, verr)
			}
		}
		return nil, err
	}
	// A SUCCESSFUL handshake that went through the blanket-accept hook would mean uTLS skipped certificate
	// verification and let us through anyway. The uTLS we build against cannot do that, but nothing in OUR
	// code makes it true and a version bump could take it away silently. Fail closed.
	if echRejected {
		uc.Close()
		return nil, errors.New("ech-reject: handshake completed with an unverified outer certificate")
	}
	conn.SetDeadline(time.Time{})
	return uc, nil
}

// echConfigVersion is the ECHConfig version (draft-ietf-tls-esni-13, 0xfe0d) that uTLS parses; any
// other-versioned config in the list is skipped. Kept in sync with utls' extensionEncryptedClientHello.
const echConfigVersion uint16 = 0xfe0d

// echPublicNames parses an ECHConfigList and returns the public_name of EVERY usable config — the SNIs
// the edge may present a certificate for when it REJECTS our stale ECH. Empty on any parse failure. ALL
// of them, not just the first: uTLS picks the first config it can actually USE, and that support set
// lives in an internal package we cannot import. The layout mirrors utls' parseECHConfig:
//
//	ECHConfigList = u16-len-prefixed configs
//	config        = u16 version + u16-len-prefixed contents
//	contents      = config_id(u8) kem_id(u16) public_key(u16) suites(u16) max_name_len(u8) public_name(u8) …
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
			continue // different-versioned config: skip its (already consumed) contents
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

// echVerifyRoots is a TEST SEAM and is nil in production, where nil means the system trust store.
// The ECH self-heal REDIAL is only reachable through a rejection that carries retry configs, and this
// verification stands between the rejection and that redial — so with no seam the redial path cannot be
// driven by a test at all, which is how a connection that gets no desync decoys survived in it.
var echVerifyRoots *x509.CertPool

// verifyECHPublicName checks the OUTER (ECH-reject) certificate chains to a public root for one of the
// ECH public names, so a network attacker can't feed the core forged RetryConfigs by presenting any
// random cert. This gates the fresh-key HARVEST before the redial: without it a MITM could inject its
// own ECH config and decrypt the redial's inner ClientHello (unmasking the real SNI).
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

// verifyOuterCert is verifyECHPublicName with an injectable trust anchor (nil -> system roots), so the
// chain + hostname logic is unit-testable against a throwaway CA without touching the system store.
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

// chromeSpec returns a freshly built current-Chrome ClientHelloSpec. A non-nil alpn overrides Chrome's
// ALPN VALUES — ["http/1.1"] for the WebSocket/POST-ladder carriers so the edge does not pick h2, nil for
// grpc to keep Chrome's h2. Only the values change, not the extension set, so the JA3 still matches
// Chrome. UTLSIdToSpec builds a fresh spec per call, so mutating its ALPN disturbs no shared parrot.
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

// establishWS opens one WebSocket connection: it picks the current pool edge (or the single configured
// one), dials it, does the wss TLS+ECH, and performs the upgrade. A failure burns nothing: the node's
// tun probe is the only judge of an edge, exactly as it is for the direct pools.
func (b *TCP) establishWS() (net.Conn, string, string, error) {
	dialAddr, host, ech, path := b.addr, b.wsHost, b.wsECH, b.wsPath
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
	conn, err := b.dialer(connectTimeout).Dial("tcp", dialAddr)
	if err != nil {
		b.pinFailedOn(dialAddr, host)
		return nil, dialAddr, "", err
	}
	// Decoys go out on the bare 4-tuple, BEFORE the wss handshake and the WebSocket upgrade below, so
	// the DPI has not yet seen the ClientHello or the Upgrade when the first decoy arrives.
	b.sendTCPFakes(conn)
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, dialAddr, host, ech, true, handshakeTimeout) // live carrier: a self-heal is panel-worthy
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

// probe is the reachability oracle the retest ladder asks. Production runs the real network probe;
// tests substitute probeFn.
func (b *TCP) probe(ip string, sni wsSNIEntry) bool {
	if b.probeFn != nil {
		return b.probeFn(ip, sni)
	}
	return b.probeEdgeFull(ip, sni)
}

// probeEdgeFull completes the FULL client control path to (ip, sni) — TCP + wss TLS/ECH + the WebSocket
// UPGRADE — then closes, with no data and no pool-state changes. A LIVE success requires the upgrade, so
// a TLS-only probe would read a broken ws/origin path behind a CDN as "reachable" and falsely heal it.
func (b *TCP) probeEdgeFull(ip string, sni wsSNIEntry) bool {
	if b.httpc {
		// The same reasoning applies to http/grpc, more so: a CDN terminates TLS for ANY of its anycast IPs,
		// so a TLS-only probe reports "reachable" for an edge whose path to the origin is dead or 502s — it
		// would falsely heal it on retest and defeat the manual-pin auto-release. Run a REAL establish and
		// tear it straight down; dialHTTPCOnce cleans up everything it allocated either way.
		host := sni.host
		if host == "" {
			host = ip
		}
		// probeTimeout is the operator's edge-probe budget, and it has to reach all three legs — the dial, the
		// TLS handshake and the header wait. The TLS one only because uEdgeHandshake TAKES it: that function
		// arms the socket deadline itself, so arming one before calling it is overwritten and lost.
		conn, err := b.dialHTTPCOnce(ip, host, sni.ech, sni.path, probeTimeout)
		if err != nil {
			// Retry ONCE with the fresh key on a stale-ECH rejection, exactly as the live path and the ws probe
			// already do. Without it a rotated ECH key makes every retest of a suspect httpc entry fail forever —
			// it walks the backoff to dead and can never come back — and poisons attribution too, since the
			// reproduce step and both isolation arms then fail for a reason unrelated to the edge.
			var echErr *utls.ECHRejectionError
			if !errors.As(err, &echErr) || len(echErr.RetryConfigList) == 0 {
				return false
			}
			log.Printf("core/http: ECH-SELFHEAL[probe] for %s (%s) — stale key rejected, retrying with the fresh one", host, ip)
			// Deliberately NOT persisted here: this mirrors tlsToEdge's live=false probe contract, where
			// a probe proves reachability but does not publish a key. The live dial persists it.
			if conn, err = b.dialHTTPCOnce(ip, host, echErr.RetryConfigList, sni.path, probeTimeout); err != nil {
				return false
			}
		}
		conn.Close()
		return true
	}
	conn, err := b.dialer(probeTimeout).Dial("tcp", ip)
	if err != nil {
		return false
	}
	host := sni.host
	if host == "" {
		host = ip
	}
	if b.wsTLS {
		tc, terr := b.tlsToEdge(conn, ip, host, sni.ech, false, probeTimeout) // probe: the operator's budget, and don't emit a self-heal event
		if terr != nil {
			return false
		}
		conn = tc
	}
	path := sni.path
	if path == "" {
		path = "/"
	}
	_, werr := wsClientHandshake(conn, host, path, time.Now().Add(handshakeTimeout))
	conn.Close()
	return werr == nil
}

// setLastErr records the CAUSE of a client carrier death for the pool's "down" event. It ignores
// "use of closed network connection" (that is us closing it, a consequence not a cause) and never
// downgrades a real cause already stored for this death to that placeholder.
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

// takeLastErr returns and clears the last recorded death cause.
func (b *TCP) takeLastErr() string {
	s, _ := b.lastErr.Load().(string)
	b.lastErr.Store("")
	return s
}

// classifyErr maps a raw carrier death cause to a stable reason CODE the panel renders into text.
// The point is a PRECISE, core-observed reason (it saw the actual error) rather than a panel guess.
func classifyErr(s string) string {
	l := strings.ToLower(s)
	switch {
	case s == "":
		return "closed"
	case strings.Contains(l, "keepalive") || strings.Contains(l, "ping"):
		return "ping_timeout" // no keepalive answer: throttled/blackholed, or the peer went away
	case strings.Contains(l, "connection reset") || strings.Contains(l, "reset by peer"):
		return "reset" // RST — often a stateful-DPI kill of an established flow
	case strings.Contains(l, "refused"):
		return "refused"
	case strings.Contains(l, "timeout") || strings.Contains(l, "deadline") || strings.Contains(l, "no route") || strings.Contains(l, "unreachable"):
		return "timeout"
	case strings.Contains(l, "eof"):
		return "eof"
	case strings.Contains(l, "tls") || strings.Contains(l, "handshake") || strings.Contains(l, "certificate"):
		return "tls" // TLS failed — a blocked SNI is often killed at the ClientHello
	case strings.Contains(l, "websocket") || strings.Contains(l, "ws ") || strings.Contains(l, "101 switching") || strings.Contains(l, "upgrade"):
		// Match the full HTTP-101 status line ("101 Switching Protocols"), not a bare "101" substring,
		// so an unrelated error that merely contains "101" (an IP octet, a port, a byte count) is not
		// misclassified as a websocket-upgrade failure.
		return "ws_upgrade" // reached TLS but the CDN/origin refused the upgrade
	default:
		return "dropped"
	}
}

// retestLoop (pooled client) periodically retests suspect/dead pool entries whose backoff has
// elapsed. Each due entry is probed against a known-healthy partner (or the active one), and
// the outcome walks the entry's FSM (success -> healthy, failure -> longer backoff / dead), so
// a temporary block heals itself with no rebuild. Runs until Close.
func (b *TCP) retestLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			b.pollWsCmd()
			if hosts := b.pool.readECHCmd(); len(hosts) > 0 { // panel live-pushed a fresh ECH key
				// Hot-swapped in memory (updateECH); the next dial presents the fresh key with no rebuild,
				// so the live core stays ahead of Cloudflare's key rotation instead of failing first.
				log.Printf("core/ws: live ECH key updated for %v (no rebuild)", hosts)
			}
			// Probe OFF the tick. Each due entry costs a full TLS + ws-upgrade round trip, and running them
			// inline made the next tick — and with it the operator's "pin this edge" — wait behind the whole
			// batch. One batch at a time, so probes never pile up on a struggling edge.
			if due := b.pool.dueRetests(); len(due) > 0 && b.probing.CompareAndSwap(false, true) {
				go func(due []retestSpec) {
					defer b.probing.Store(false)
					for _, spec := range due {
						if b.closed.Load() {
							return
						}
						// Full TLS+ws-upgrade probe so a suspect isn't falsely healed by a TLS-only
						// success on an edge whose ws/origin path is actually broken.
						b.pool.retestResult(spec.kind, spec.key, b.probe(spec.ip, spec.sni))
					}
				}(due)
			}
		}
	}
}

// readECHCmdSingle consumes a pending live ECH-key push for a SINGLE (non-pool) ws/http edge and
// hot-swaps b.wsECH so the NEXT dial presents it — the single-edge counterpart to the pool's readECHCmd,
// off the same <status>.echcmd sidecar the node writes for both. Called only from dialLoop, the sole
// writer of b.wsECH, so no lock is needed.
func (b *TCP) readECHCmdSingle() bool {
	if !b.ws || b.wsHost == "" || b.st == nil {
		return false // pools (b.st nil) and non-ws carriers never carry a single-edge ECH key here
	}
	cp := b.st.path + ".echcmd"
	data, err := os.ReadFile(cp)
	if err != nil {
		return false
	}
	os.Remove(cp) // consume once: a fresh push rewrites it atomically
	var c struct {
		SNIs map[string]string `json:"snis"`
	}
	if json.Unmarshal(data, &c) != nil || len(c.SNIs) == 0 {
		return false
	}
	b64, ok := c.SNIs[b.wsHost]
	if !ok {
		return false
	}
	ech, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if derr != nil || len(ech) == 0 || bytes.Equal(b.wsECH, ech) {
		return false // undecodable or unchanged -> nothing to swap
	}
	b.wsECH = ech
	return true
}

const (
	// reconnectBase / reconnectMax bound the client re-dial backoff. A periodic SYN/handshake train to a
	// filtered IP is itself a tunnel signature that confirms the endpoint to a censor, so the delay
	// doubles (jittered) while dials keep failing and resets to base once a connection is established.
	reconnectBase = 1 * time.Second
	reconnectMax  = 60 * time.Second
)

// nextReconnectDelay advances the exponential re-dial backoff: reconnectBase when cur==0, else
// min(cur*2, reconnectMax), jittered so the retry carries no fixed period.
func nextReconnectDelay(cur time.Duration) time.Duration {
	next := reconnectBase
	if cur > 0 {
		if next = cur * 2; next > reconnectMax {
			next = reconnectMax
		}
	}
	return jitterFrac(next)
}

// warmDial is a carrier that is already connected and handshaked, waiting to replace the live one.
type warmDial struct {
	cf    *connFramer
	conn  net.Conn
	label string
	combo string
	// srcAddr is the source IP a PROACTIVE beat rotated onto for this carrier ("" when the source did
	// not move). It rides here so the src-rotate event is published at the adoption site — where this
	// carrier goes live — instead of in the timer, mirroring how `label` defers the dest peer-rotate.
	srcAddr string
	// dstMoved records whether the DESTINATION pool actually advanced on the beat that built this
	// carrier. A beat fires when EITHER pool moves, so without this the adoption site announced a
	// destination rotation on a source-only beat — naming an endpoint the tunnel never left.
	dstMoved bool
}

// buildWarm dials and handshakes the destination pool's CURRENT endpoint and parks the result for
// dialLoop, WITHOUT touching the live connection. It returns false when that endpoint will not come up,
// so the caller keeps the healthy one. A failure is attributed like a primary dial (it still burns) and
// the cursor goes back to dstPrev, so the pool never publishes an endpoint the tunnel never left for.
func (b *TCP) buildWarm(burn func(), srcAddr string, dstMoved bool, dstPrev string) bool {
	if b.closed.Load() {
		return false
	}
	conn, label, combo, err := b.dialCarrier()
	if err != nil {
		burn()
		b.pp.keepCursorOn(dstPrev)
		return false
	}
	cf, err := b.handshakeAndPrime(conn)
	if err != nil {
		conn.Close()
		burn() // answers TCP but will not carry the tunnel — same attribution the primary path uses
		b.pp.keepCursorOn(dstPrev)
		return false
	}
	// Anything already parked belongs to a dialLoop iteration that never adopted it: its connection died
	// while that build was in flight. Adopting it later logs a connect on a carrier that then dies at
	// once, and failing here instead wedges rotation — so close the stale one and park the fresh one.
	if stale := b.takeWarm(); stale != nil {
		stale.conn.Close()
	}
	select {
	case b.warmNext <- &warmDial{cf: cf, conn: conn, label: label, combo: combo, srcAddr: srcAddr, dstMoved: dstMoved}:
		return true
	default:
		conn.Close() // another build won the slot (overlapping timers) — drop this one
		b.pp.keepCursorOn(dstPrev)
		return false
	}
}

// takeWarm returns a parked warm connection, or nil.
func (b *TCP) takeWarm() *warmDial {
	if b.warmNext == nil {
		return nil
	}
	select {
	case w := <-b.warmNext:
		return w
	default:
		return nil
	}
}

// dialLoop (client) keeps a connection to the server alive, retrying on drop. For a
// ws pool it rotates edges: each attempt uses the pool's current (IP × SNI), a
// failure burns the offending IP/SNI (establishWS), and a proactive timer tears the
// connection down after b.rotate so the client moves before the edge is fingerprinted.
func (b *TCP) dialLoop() {
	b.warmNext = make(chan *warmDial, 1)
	defer func() {
		if w := b.takeWarm(); w != nil {
			w.conn.Close() // built just as Close fired — do not leak the fd
		}
	}()
	// reconnect backoff: grows on each failed dial/handshake, resets on a successful connect, so a
	// dead/blocked destination is re-probed with an exponential backoff instead of a fixed-1s beacon.
	backoff := time.Duration(0)
	for {
		if b.closed.Load() {
			return
		}
		if b.readECHCmdSingle() { // panel live-pushed a fresh ECH key for this single edge — use it on THIS dial
			log.Printf("core/ws: live ECH key updated for %s (single edge, no rebuild)", b.wsHost)
		}
		// A timed rotation parks the next carrier here, already connected and handshaked, so this
		// iteration costs neither a connect nor a handshake — that is what removes the rotation gap.
		w := b.takeWarm()
		if w != nil && b.directPinInForce() {
			// A parked rotation carrier resolved its endpoint at BUILD time, before this pin existed, and the
			// adoption path below reuses that connection verbatim. Adopting it under a pin would publish the
			// rotation's endpoint as active and release the pin as if it had landed, while the tunnel sat on a
			// different IP. Drop it and dial fresh — dialCarrier re-reads current(), which forces the pin.
			log.Printf("core/tcp: dropping the pre-built rotation carrier — an operator pin is pending")
			w.conn.Close()
			w = nil
		}
		var conn net.Conn
		var label, combo string
		var cf *connFramer
		if w != nil {
			conn, label, combo, cf = w.conn, w.label, w.combo, w.cf
			// A timed rotation only becomes REAL here, when the warm carrier goes live, so it is published here
			// with the endpoint the connection is genuinely on. event() rather than down(): the changeover is
			// seamless, and arming a reconnect would make every rotation read as a drop plus a self-heal. Only
			// when the DESTINATION really advanced — a beat fires when either pool moves.
			if b.pp != nil && w.dstMoved {
				b.st.setActive(b.stTag + " · " + label)
				b.st.event("down", "peer-rotate", "ip:"+label)
			}
			// A proactive source rotation is announced HERE, where the warm carrier actually goes live, so a
			// failed warm build never logs a move that did not happen. Adoption alone is not enough: dialer()
			// installs no LocalAddr for a source that is not on this host, so the socket leaves from the KERNEL
			// DEFAULT while the connect still succeeds — hence the lastSourceUsed() compare, which only suppresses.
			if w.srcAddr != "" && b.lastSourceUsed() == w.srcAddr {
				b.st.event("down", "src-rotate", "ip:"+w.srcAddr)
			}
		} else {
			var err error
			conn, label, combo, err = b.dialCarrier() // logs the transport failure itself
			if err != nil {
				if b.pool != nil {
					b.pool.advance() // rotate to the next combo for the retry
				}
				// A DIRECT pool is left alone: only the node's tun probe may condemn one of its
				// endpoints, and a dial that failed says the carrier could not come up, not which IP
				// is to blame. Re-dial on the backoff; the probe judges within a couple of sweeps.
				backoff = nextReconnectDelay(backoff)
				if b.sleep(backoff) {
					return
				}
				continue
			}
			cf, err = b.handshakeAndPrime(conn)
			if err != nil {
				conn.Close()
				// The ws EDGE pool attributes this itself — a TCP connect that completes and then fails the
				// core handshake is the signature of a DPI that lets the SYN through and kills the payload.
				// A DIRECT pool does not: the tun probe is its only judge, and it sees the same silence.
				if b.pool != nil {
					b.pool.advance() // rotate to the next combo; the tun probe judges which one is blocked
				}
				backoff = nextReconnectDelay(backoff)
				if b.sleep(backoff) {
					return
				}
				continue
			}
		}
		log.Printf("core/tcp: connected to %s", label)
		backoff = 0 // the endpoint answered — a later re-dial starts from reconnectBase again
		connectedAt := time.Now()
		// Single-edge (non-pool) self-heal: pair this recovery with a prior carrier-loss "down". nil-safe
		// (no-op when no status file is wired) and silent on the first connect (only a pending down emits).
		b.st.reconnected(label)
		// Clear a STALE manual-switch flag before this connection's death is ever accounted. rotate1 sets it
		// unconditionally, so one issued during an outage has no death to consume it and would mask the NEXT
		// genuine death as a clean switch. A pin that drops THIS carrier re-sets it during its life.
		b.manualSwitch.Store(false)
		b.cur.Store(cf)
		b.adoptRx(cf) // this carrier is the tunnel now: publish the heartbeat it already proved
		cc := conn
		b.curConn.Store(&cc) // expose the live conn so RotateIP/RotateSNI can drop it
		if b.pool != nil {
			// Record the edge we ACTUALLY connected on as the live active and flush the status
			// file, so a plain rotation reflects the new active immediately (the panel reads this
			// field and logs the auto-switch off its change). setActive is the single writer of the
			// active edge — current() no longer touches it.
			b.pool.setActive(combo)
			// A pin that targeted this edge has now LANDED — release it so a healthy pin does not freeze
			// rotation while the pin is in force (current() forces the pinned edge, and the rotation
			// timer skips every beat while isPinned()). The warm loop already does this on connect; the
			// non-warm loop must too. No-op when no pin is in force (single-locked, no TOCTOU).
			b.pool.pinApplied(label, strings.TrimPrefix(combo, label+" · "))
		} else {
			// Direct pp/sp: release an operator pin that has now landed (a pin is "jump here and keep trying
			// until connected"). pinLandedOn is single-locked, a no-op when no pin is in force, and it COMPARES —
			// a pin is never consumed by a carrier that resolved its endpoint before the pin existed.
			if b.pp != nil {
				b.pp.pinLandedOn(label)
			}
			if b.sp != nil {
				b.sp.pinLandedOn(b.lastSourceUsed())
			}
		}
		// Proactive rotation: after b.rotate, advance the pool and drop this connection
		// so dialLoop reconnects on the next edge. A connection that dies on its own
		// keeps the same edge — the timer is stopped before that path runs.
		var rot *time.Timer
		var rotated atomic.Bool
		// rotp publishes the timer TO ITS OWN callback. `rot = time.AfterFunc(...)` leaves the callback
		// reading the very variable the setup goroutine is still assigning -- a data race, even though a
		// positive interval means it cannot be observed in practice. A fire before the Store simply does
		// not re-arm and returns without advancing, which is benign.
		var rotp atomic.Pointer[time.Timer]
		rearm := func(d time.Duration) {
			if t := rotp.Load(); t != nil {
				t.Reset(d)
			}
		}
		// timerLive gates the rotation callback's SELF re-arm. A pinned/no-move beat re-arms via rearm,
		// which races the rot.Stop() below; clearing timerLive BEFORE Stop makes any post-teardown fire
		// return at once without advancing or re-arming, so a leaked beat self-terminates.
		var timerLive atomic.Bool
		timerLive.Store(true)
		if b.pool != nil && b.rotate > 0 {
			c := conn
			// Arm the rotation timer regardless of the CURRENT pin state and re-check the pin when it FIRES. A
			// pin is applied by re-dialing onto the chosen edge, so isPinned() is true at this connection's
			// setup — gating the ARM on it froze rotation for the whole life of a healthy connection. Now the
			// pin only holds rotation off for its own window.
			rot = time.AfterFunc(b.rotate, func() {
				if !timerLive.Load() {
					return // this connection is being torn down — do not advance or re-arm
				}
				if b.pool.isPinned() {
					rearm(b.rotate) // still pinned — hold rotation off, but keep checking (never freeze)
					return
				}
				// Only drop the live connection when the pool can actually reach a DIFFERENT edge. With every other
				// combo burned, advance() resolves straight back to this one, and closing anyway costs a
				// re-dial + handshake + traffic gap every interval for nothing. `rotated` is set only once the
				// close is really happening, so a skipped beat is never mistaken for a deliberate rotation.
				if !b.pool.advance() {
					rearm(b.rotate) // re-arm so rotation resumes as soon as another edge heals
					return
				}
				rotated.Store(true)
				c.Close()
			})
			rotp.Store(rot)
		} else if (b.pp != nil && b.pp.rotate > 0) || (b.sp != nil && b.sp.rotate > 0) {
			c := conn
			iv := time.Duration(0) // fire on whichever pool has the (longer) rotate interval set
			if b.pp != nil {
				iv = b.pp.rotate
			}
			if b.sp != nil && b.sp.rotate > iv {
				iv = b.sp.rotate
			}
			// Only tear the live connection down if a pool ACTUALLY advanced. When every other endpoint
			// is burned (the common "one IP got filtered" steady state) rotateOnce() can't move; closing
			// anyway would drop a healthy connection every interval for nothing (cf. the datagram guard).
			rot = time.AfterFunc(iv, func() {
				if !timerLive.Load() {
					return // this connection is being torn down — do not advance or re-arm
				}
				if (b.pp != nil && b.pp.isPinned()) || (b.sp != nil && b.sp.isPinned()) {
					rearm(iv) // an operator pin freezes rotation for its window — re-arm, never freeze for the life of the conn
					return
				}
				// dstMoved is carried to the adoption site, not just folded into `moved`: a beat fires
				// when EITHER pool advances, so announcing a destination rotation off `moved` alone
				// described a destination move on a source-only beat.
				dstMoved := false
				dstPrev := "" // where the LIVE connection is; restored below if the warm build fails
				// The two pools are an ODOMETER: each beat advances the destination, and the source
				// moves only once the destination has been all the way round — or cannot move at all.
				// See rotationController.proactive; tcp runs its own timer but the walk is the same.
				lap := true
				if b.pp != nil {
					dstPrev = b.pp.current()
					if _, m := b.pp.rotateOnce(); m {
						dstMoved = true // the endpoint itself is read back at the adoption site, once it is real
					}
					n := int32(b.pp.eligibleCount())
					lap = !dstMoved || (n > 0 && b.destTick.Add(1) >= n)
					if lap {
						b.destTick.Store(0)
					}
				}
				moved := dstMoved
				// srcMovedTo is announced at the adoption site, not here — see rotateSourceTCP.
				srcMovedTo := ""
				if lap {
					if a, m := b.rotateSourceTCP(true); m { // the odometer's high digit
						moved = true
						srcMovedTo = a
					}
				}
				if !moved {
					rearm(iv) // every other endpoint burned this beat — re-arm so rotation resumes once one heals
					return
				}
				// MAKE BEFORE BREAK. A connection-oriented carrier cannot carry its session across a destination
				// change the way the datagram carriers do, so build the NEXT one first and only then drop this one:
				// dialLoop adopts the parked carrier without dialing, so the changeover costs no connect.
				if !b.buildWarm(func() {}, srcMovedTo, dstMoved, dstPrev) { // live carrier stays: silent, its endpoint is still Active
					// The endpoint we advanced onto will not come up. KEEP the healthy connection —
					// trading it for a dead one is exactly what make-before-break exists to prevent —
					// and re-arm. Nothing is burned: a warm build that failed is not the tun probe
					// speaking. buildWarm has already put the cursor back on dstPrev.
					rearm(iv)
					return
				}
				if !timerLive.Load() || b.closed.Load() {
					// The live connection died (or Close fired) while the warm carrier was being built,
					// so dialLoop has already moved on and its defer may have run. Reclaim the conn here
					// rather than leave it parked for a later iteration to adopt as though it were fresh.
					if w := b.takeWarm(); w != nil {
						w.conn.Close()
					}
					return
				}
				rotated.Store(true)
				c.Close()
				// The rotation is published where it BECOMES REAL — the adoption site in dialLoop — not
				// here. Announcing it from the timer described a move that a failed warm build never
				// made, left "active" naming an endpoint the tunnel was not on, and armed a down() the
				// next connect paired as a phantom self-heal.
			})
			rotp.Store(rot)
		}
		b.serve(cf)            // blocks until this connection dies
		timerLive.Store(false) // disable the callback's re-arm before stopping, so a racing beat can't re-arm
		if rot != nil {
			rot.Stop()
		}
		b.curConn.CompareAndSwap(&cc, nil)
		b.cur.CompareAndSwap(cf, nil)
		// Classify why this carrier died and feed the pool's health + event log. A drop we caused
		// ourselves — an operator pin/rotate, or a scheduled proactive rotation — is NOT a failure
		// and is not logged as "down". A genuine death records a precise core-observed "down" reason.
		deliberate := false // a proactive rotation / operator pin that WE induced — re-dial at once, no backoff
		if b.pool != nil && !b.closed.Load() {
			cause := b.takeLastErr()
			if b.manualSwitch.Swap(false) || rotated.Load() {
				deliberate = true
				b.endRound()
			} else {
				b.pool.down(classifyErr(cause), label) // arms the paired "up" the next reconnect emits
				if time.Since(connectedAt) < minLiveness {
					// A short-lived carrier is NOT a verdict on this edge — the tun probe decides that,
					// the same way it does for the direct pools. Still move off it though: a dial that
					// succeeds puts no sleep on the path, so re-dialing the same edge spins
					// connect -> die -> reconnect with nothing slowing it down.
					b.pool.advance()
				} else {
					b.endRound() // a sustained session ends the round: the counters it fed are stale
				}
			}
		} else if (b.pp != nil || b.sp != nil) && !b.closed.Load() {
			// Direct-tcp peer/source pool: a proactive rotation or an operator jump is deliberate — clear
			// transient burns, no fault, no "down". A death sooner than minLiveness means the endpoint connected
			// but could not carry data (throttle/blackhole), so burn+advance off it. A death after a healthy
			// lifetime is an ordinary drop: keep the endpoints and clear stale burns.
			if b.manualSwitch.Swap(false) || rotated.Load() {
				deliberate = true
				b.endRound()
			} else if time.Since(connectedAt) < minLiveness {
				// a short-lived carrier is not a verdict on this endpoint; the tun probe decides
			} else {
				b.endRound()
			}
		}
		// Single-edge (non-pool) status file: surface a GENUINE carrier loss as a precise "down", paired with
		// the "up" the next successful dial emits. b.st is only ever wired on a non-pool carrier; nil-safe,
		// and skipped for a deliberate switch or Close. The branches above do not consume takeLastErr.
		if b.st != nil && !deliberate && !b.closed.Load() {
			b.st.down(classifyErr(b.takeLastErr()), label)
		}
		// Only back off before re-dialing on a GENUINE drop. A deliberate, healthy rotation re-dials at once,
		// so the switch gap is one reconnect+handshake rather than that plus a fixed second. A re-dialed edge
		// that then dies for real hits this backoff on its NEXT, non-deliberate drop.
		if !deliberate {
			backoff = nextReconnectDelay(backoff)
			if b.sleep(backoff) {
				return
			}
		}
	}
}

// dialCarrier opens the transport connection for ONE dial attempt: a pool/single ws or httpc edge, or a
// plain/cover TCP dial. It returns the live
// conn and a label for logging, and logs the transport-level failure itself so callers only decide retry
// policy. It does NOT frame or handshake.
func (b *TCP) dialCarrier() (net.Conn, string, string, error) {
	if b.ws { // pool or single edge: dial + wss(+ECH) + upgrade, burning on failure
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
	target := b.dialTarget() // the rotation pool's current endpoint, or the fixed peer
	c, err := b.dialer(connectTimeout).Dial("tcp", target)
	if err != nil {
		log.Printf("core/tcp: dial %s failed: %v", target, err)
		return nil, target, "", err
	}
	// Decoys go out on the bare 4-tuple, BEFORE the TLS cover handshake below, so the DPI has not yet
	// seen the ClientHello when the first decoy arrives.
	b.sendTCPFakes(c)
	if b.cover { // wrap in a Chrome-fingerprinted TLS session carrying the auth token
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

// coverProbeHint names the two causes behind ONE indistinguishable symptom on a cover tunnel: the TLS
// handshake succeeds and the core handshake behind it fails. tlscover answers an auth token it cannot
// open — mismatched PSK, or a clock outside its replay window — by proxying to the REAL cover site,
// which is what makes the carrier probe-resistant, so the hint has to be local. Once per carrier.
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

// handshakeAndPrime wraps a freshly-dialed conn in a framer, runs the client ephemeral handshake
// (crypto) and the obfs salt exchange, then primes the server with a ping that authenticates us.
// On any failure the returned error is non-nil and the caller closes conn. On success the framer
// is fully established and ready for serve/readLoop.
func (b *TCP) handshakeAndPrime(conn net.Conn) (*connFramer, error) {
	// The decoy injection is NOT here: it has to land on the freshly-connected 4-tuple before ANY of our
	// own bytes flow, and by this point conn may already be a TLS-cover or WebSocket session. It runs in
	// dialCarrier/establishWS instead, on the bare TCP conn each of them just dialled.
	cf := b.newFramer(conn)
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	if b.cryptoOn { // ephemeral handshake first: establishes the session sealer
		if err := b.clientHandshake(cf); err != nil {
			b.coverProbeHint()
			return nil, err
		}
		// A completed crypto handshake means the SERVER answered — an end-to-end authentication a CDN edge
		// cannot fake — so this is genuine INBOUND proof. It is recorded on THIS CONNECTION, not on the
		// tunnel: this also builds carriers that are not (yet) the tunnel's, and crediting those is a false
		// green. adoptRx publishes it the moment the carrier actually goes live.
		cf.rxAt.Store(time.Now().UnixNano())
	}
	if b.obfs {
		if err := cf.sendSalt(); err != nil { // client speaks first (length-mask salt)
			return nil, err
		}
	}
	// The prime ping is the client's first real write on this connection, and the only one on this path:
	// sendSalt above only fills saltPend, so it can fail on RNG/cipher errors alone. Discarding this error
	// would report success for a connection whose very first byte never left the box.
	if err := cf.writeFrame(typePing, nil); err != nil { // prime + authenticate us to the server
		return nil, err
	}
	// Deliberately do NOT stamp b.lastRx here: this ping is something WE sent, and lastRx means "last
	// authenticated INBOUND frame". Crediting it lets a client whose dial always succeeds but which never
	// receives a frame report "connected" forever. Only readLoop may stamp it.
	return cf, nil
}

// RotateIP / RotateSNI are the live "rotate now" controls for a ws edge pool: they advance
// a single dimension and drop the current carrier connection, so dialLoop immediately
// re-dials on the new edge. The TUN device stays up throughout (only the sub-second carrier
// redial happens) — no rebuild, no interface teardown. No-op unless this is a pooled client.
func (b *TCP) RotateIP()  { b.rotate1(func() { b.pool.advanceIP() }) }
func (b *TCP) RotateSNI() { b.rotate1(func() { b.pool.advanceSNI() }) }

// ProbeAllNow forces an immediate retest of every suspect/dead pool entry (backs the
// panel "probe now" button, delivered as a signal that carries no key). No-op unless pooled.
func (b *TCP) ProbeAllNow() {
	if b.pool != nil {
		b.pool.probeAllNow()
	}
	if b.pp != nil {
		b.pp.probeAllNow()
	}
	if b.sp != nil {
		b.sp.probeAllNow()
	}
}

// peerPinPollLoop polls the direct destination/source pools' cmd files on a 1s ticker; a pending pin
// pins the requested endpoint and drops the live carrier so dialLoop immediately re-dials onto it
// (dialTarget()/sourceIP() read the pinned endpoint via the pool's current()). No rebuild — the TUN
// stays up. Runs until Close. The ws edge pool uses retestLoop for the same job on its own axes.
func (b *TCP) peerPinPollLoop() {
	drop := func() {
		b.manualSwitch.Store(true) // operator-initiated: skip fault accounting on the induced drop
		if c := b.curConn.Load(); c != nil {
			(*c).Close() // unblocks serve(); dialLoop re-dials on the pinned endpoint
		}
	}
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			if b.pp != nil {
				if cmd, ok := b.pp.readCmd(); ok {
					switch {
					case cmd.Cmd == cmdOK:
						// Both ends of the pair the probe measured are proven; keyed, so a verdict that
						// crossed with a re-dial cannot clear an endpoint the tunnel has already left.
						if cmd.Key != "" && b.pp.clearBurn(cmd.Key) {
							b.st.event("heal", "peer-retest", "ip:"+cmd.Key)
						}
						if b.sp != nil && cmd.Src != "" && b.sp.clearBurn(cmd.Src) {
							b.st.event("heal", "src-retest", "ip:"+cmd.Src)
						}
					case cmd.Cmd == cmdFail && cmd.Key == b.pp.current():
						// Same burn the carrier does on a dead peer; burnAdvance leaves the event to its
						// caller, so publish here and drop so dialLoop re-dials on the new destination.
						// The event names the KEY, never burnAdvance's return: that is where the pool
						// moved TO, and blaming the replacement is the mis-target one step later.
						gone := cmd.Key
						if addr, moved := b.burnAdvance(true); moved {
							log.Printf("core/tcp: destination %s failed by the node's tun probe — burning and advancing to %s", gone, addr)
							b.st.event("burn", "tun-probe", "ip:"+gone)
							drop()
						}
					case cmd.Cmd == cmdFail:
						// The rotation moved between the measurement and this read (this ticker is 1s and
						// the probe ahead of it takes most of a second). Burn what was MEASURED and leave
						// the connection alone — it is already somewhere no verdict covers.
						if b.pp.burnNamed(cmd.Key) {
							log.Printf("core/tcp: destination %s failed by the node's tun probe, but the rotation has since moved to %s — burning what was measured, staying put", cmd.Key, b.pp.current())
							b.st.event("burn", "tun-probe", "ip:"+cmd.Key)
						}
					case cmd.Key != "" && b.pp.selectEntry(cmd.Key):
						log.Printf("core/tcp: pin destination %s (panel select)", cmd.Key)
						b.st.setActive(b.stTag + " · " + cmd.Key) // reflect the pinned destination in "active" — silently; drop() below is deliberate (no event)
						drop()
					}
				}
			}
			if b.sp != nil {
				// pins only: a tun probe cannot tell a bad SOURCE from a bad DESTINATION
				if cmd, ok := b.sp.readCmd(); ok && cmd.Key != "" && b.sp.selectEntry(cmd.Key) {
					log.Printf("core/tcp: pin source %s (panel select)", cmd.Key)
					drop()
				}
			}
		}
	}
}

// pollWsCmd reads one pending node command for the edge pool and acts on it: a tun-probe verdict
// (burn/heal) or the panel's pin. Split out of the ticker so the whole wire — file, keying,
// decision — is drivable end to end.
func (b *TCP) pollWsCmd() {
	if cmd, ok := b.pool.readCmd(); ok {
		switch {
		case cmd.Cmd == cmdOK:
			// The probe found traffic crossing, so BOTH halves of the combo it measured are
			// proven. Cleared separately: the two axes rotate independently and either can
			// slide under a verdict.
			if cmd.IP != "" && b.pool.clearBurn("ip", cmd.IP) {
				b.pool.event("heal", "tun-probe", "ip:"+cmd.IP)
			}
			if cmd.SNI != "" && b.pool.clearBurn("sni", cmd.SNI) {
				b.pool.event("heal", "tun-probe", "sni:"+cmd.SNI)
			}
		case cmd.Cmd == cmdFail:
			// The verdict names the COMBO it was measured on, and that name is the whole guard:
			// this is a ticker and the carrier rotates on its own timers, so a verdict that
			// crossed with a rotation would otherwise condemn a combo the probe never tested.
			// Both arms live in THIS case, never as sibling cases: a fail must not fall through
			// to the pin arm below and select the very edge it condemns.
			ip, sni := b.pool.activeCombo()
			if cmd.IP == ip && cmd.SNI == sni {
				if b.burnAdvanceWS(ip, sni) {
					log.Printf("core/ws: %s%s%s failed by the node's tun probe — burning the axis the walk varies and advancing", ip, activeSep, sni)
					b.manualSwitch.Store(true) // induced drop: no fault accounting on top of the verdict
					if c := b.curConn.Load(); c != nil {
						(*c).Close() // unblocks serve(); dialLoop re-dials on the next combo
					}
				}
			} else if cmd.SNI != "" {
				// It moved under the verdict. Burn what was MEASURED and leave the connection
				// alone: it is already somewhere no verdict covers.
				log.Printf("core/ws: %s%s%s failed by the node's tun probe, but the carrier has since moved to %s%s%s — burning what was measured, staying put",
					cmd.IP, activeSep, cmd.SNI, ip, activeSep, sni)
				b.pool.markSuspect("sni", cmd.SNI, "tun-probe")
			}
		case cmd.Key != "": // panel "pin this edge" request
			log.Printf("core/ws: select edge %s=%s (panel pin)", cmd.Kind, cmd.Key)
			b.SelectEdge(cmd.Kind, cmd.Key)
		}
	}
}

// burnAdvanceWS is the ws edge pool's half of the odometer, and the exact mirror of burnAdvance: the
// SNI is the low digit and burns, the EDGE is the high digit and only WALKS — a tun probe sees silence,
// which names the combo it measured and never one axis, so the edge is convicted only by a whole lap of
// SNIs failing on it. A pool with ONE SNI has no low digit at all, and there the edge is what varies and
// what burns. Returns whether the pool actually moved, so the caller only drops a live carrier that has
// somewhere else to land.
func (b *TCP) burnAdvanceWS(ip, sni string) bool {
	// Same second opinion as every other carrier. It used to release on the FIRST verdict (markSuspect
	// dropped the pin as it burned), which broke the operator's pick on one measurement while udp/raw/flux
	// asked for two.
	if b.pool.isPinned() {
		if n := b.pinFails.Add(1); int(n) < pinFailRelease {
			return false
		}
		b.pinFails.Store(0)
		b.pool.releasePin()
		// pin cleared — fall through and burn+advance off the blocked combination this round
	} else {
		b.pinFails.Store(0)
	}
	// Burn whatever the walk actually VARIES. That is the whole attribution: the probe sees silence,
	// silence names the COMBINATION, and only the axis being changed between combinations can be told
	// apart from the one that is not.
	//
	// With two or more SNIs the walk varies the SNI, so the SNI burns and the edge is convicted only by a
	// whole row failing on it. With exactly ONE SNI there is no SNI axis: every beat changes the EDGE, so
	// the edge is what varies and the edge is what burns. Burning the lone SNI instead was worse than
	// useless -- advanceEdgeFreshRow cleared the row on the very next line, so the burn was undone as
	// fast as it was made and NO edge was ever blacklisted. A pool advertised as "rotate + blacklist"
	// only rotated: a dead edge came back every cycle, dropped the tunnel, and was walked off again.
	if b.pool.snisCount() < 2 {
		b.pool.markSuspect("ip", ip, "tun-probe")
		b.pool.advanceIP()
		b.sniRot.Store(0)
		return true
	}
	// Size the lap ONCE, at the start of the round: ELIGIBLE SNIs, before the first burn. Re-reading it
	// every ask is the trap — each burn shrinks the count the next ask compares against, so three SNIs
	// declare a lap after two and the edge is convicted a step early. Floored at one: with nothing else
	// eligible, the SNI we are sitting on IS the whole experiment.
	want := b.sniWant.Load()
	if b.sniRot.Load() == 0 {
		want = int64(b.pool.eligibleSNIs())
		b.sniWant.Store(want)
	}
	if want < 1 {
		want = 1
	}
	b.pool.markSuspect("sni", sni, "tun-probe")
	if n := b.sniRot.Add(1); n >= want {
		b.pool.advanceEdgeFreshRow() // every SNI that could be tried has been — the edge is what did not vary
		b.sniRot.Store(0)
	}
	return true
}

// SelectEdge pins a specific pool edge (kind "ip"|"sni", key its value) as the active one and
// drops the live carrier so dialLoop immediately re-dials onto it — the TUN stays up. This is
// the exact-jump behind the panel's per-edge pin button (delivered via the node's cmd file,
// since a signal can't carry the key). No-op unless pooled.
func (b *TCP) SelectEdge(kind, key string) {
	if b.pool == nil {
		return
	}
	b.rotate1(func() { b.pool.selectEntry(kind, key) })
}

func (b *TCP) rotate1(step func()) {
	if b.pool == nil {
		return
	}
	step()
	b.manualSwitch.Store(true) // operator-initiated: skip fault accounting; warm loop re-dials via current()
	if c := b.curConn.Load(); c != nil {
		(*c).Close() // unblocks serve(); dialLoop re-dials on the advanced/pinned edge
	}
}

// handleFrame dispatches a single decoded frame.
func (b *TCP) handleFrame(cf *connFramer, typ byte, payload []byte) {
	switch typ {
	case typePing:
		_ = cf.writeFrame(typePong, nil)
	case typePong:
		// Nothing to record: readLoop already cleared cf.unanswered for this frame, which is the whole
		// of what a pong is for now. The rtt it used to time went to a status field nobody read.
	case typeData:
		b.lastRxData.Store(time.Now().UnixNano()) // real INBOUND data -> the keepalive ping is redundant this interval
		// Downstream follows upstream DATA (server only): the connection the client most recently sent a
		// real data frame on becomes the TUN->client target, so a client that re-dialled flips the server
		// within one frame with no explicit signalling while its old conn, which sends nothing, never
		// steals it back. Ping/pong must NOT move it.
		if !b.isClient {
			b.cur.Store(cf)
		}
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("core/tcp: tun write error: %v", err)
		}
	}
}

// serve reads framed messages from one connection until it errors or closes. onConnErr clears the live
// pointer on exit, so both the client (which redials) and the server converge on "no live connection"
// without extra bookkeeping. The read deadline is refreshed every frame in ALL modes, so a peer that
// dies without a FIN/RST is reaped instead of pinning a goroutine forever.
func (b *TCP) serve(cf *connFramer) {
	b.onConnErr(cf, b.readLoop(cf))
}

// adoptRx moves the TUNNEL's heartbeat onto the carrier that has just become live, taking that carrier's
// OWN last authenticated inbound frame — the crypto handshake the responder answered. hb only ever moves
// FORWARD (a fresh carrier can hold an older rxAt than the outgoing one's last frame), and the CAS
// settles the race with the carrier's own reader.
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

// readLoop reads framed messages from one connection until it errors or closes, dispatching each to
// handleFrame. It does NOT touch b.cur/authConns, so a caller may run it per-connection and own the
// pointer transitions itself; serve wraps it with onConnErr for the client and every server connection.
// The read deadline is refreshed every frame in ALL modes.
func (b *TCP) readLoop(cf *connFramer) error {
	for {
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
		typ, session, seq, payload, err := cf.readFrame()
		if err != nil {
			return err
		}
		if cf.sealer != nil && !cf.rp.ok(session, seq) {
			// Authenticated but replayed/duplicate -> ignore and keep the connection, but do NOT credit it as
			// liveness: a replay can be a stale duplicate or an on-path re-injection of a captured frame, so
			// resetting ping-loss here would pin a black-holed carrier "alive". Only a FRESH frame proves the peer.
			continue
		}
		cf.unanswered.Store(0) // a fresh inbound frame proves the peer is alive -> reset ping-loss
		now := time.Now().UnixNano()
		cf.rxAt.Store(now) // THIS connection's own liveness, per connection and not per carrier
		// ...but only the LIVE carrier may stamp the TUNNEL's heartbeat. Every connection runs its own
		// readLoop, so an unguarded stamp lets a conn that is NOT the live one keep hb fresh while b.cur is
		// empty — green on the panel while every packet is dropped. b.cur is set before the reader starts on
		// every client path, so the live carrier's own frames are never missed.
		if cf == b.cur.Load() {
			b.lastRx.Store(now)
		}
		b.handleFrame(cf, typ, payload)
	}
}

func (b *TCP) onConnErr(cf *connFramer, err error) {
	if b.isClient {
		b.setLastErr(err) // remember the cause so dialLoop can log a precise pool "down" reason
	}
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil) // only clear downstream if THIS conn was the target
	b.removeAuthConn(cf)          // server: drop from the authenticated set (no-op on the client)
	if !b.isClient {
		b.reelectDownstream() // ...and hand downstream to a surviving authenticated conn, if any
	}
	if !b.closed.Load() {
		log.Printf("core/tcp: connection closed: %v", err)
	}
}

// tunLoop reads L3 packets from TUN and writes them to whichever connection is
// currently live. Packets that arrive while no connection is up are dropped
// (the peer retransmits at the L4 layer).
func (b *TCP) tunLoop() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if b.closed.Load() {
				return nil // deliberate shutdown: Close() is what made the read fail
			}
			// The device is gone and this carrier can never move another packet. Hand it back so Run
			// returns and the process exits to be restarted, exactly as udp/raw/flux do — staying up
			// here is what produced a green tunnel carrying nothing.
			log.Printf("core/tcp: tun read error: %v", err)
			return err
		}
		cf := b.cur.Load()
		if cf == nil {
			continue // no live peer connection yet
		}
		if err := cf.writeFrame(typeData, buf[:n]); err != nil {
			if errors.Is(err, errFrameTooBig) {
				// A single packet too large to frame (a GSO/jumbo super-packet past the TUN MTU): DROP it
				// and keep the carrier. Closing here would re-read the same packet after reconnect and
				// close again — a poison packet that flaps the tunnel forever. The peer's L4 retransmits a
				// correctly-sized segment; a proper TUN MTU stops this arising at all.
				log.Printf("core/tcp: dropping oversize packet (%d bytes) — too large to frame", n)
				continue
			}
			b.onConnErr(cf, err)
			continue
		}
		// Write succeeded: real DATA moved OUTBOUND. That counts as liveness for the IDLE REAPER only — a
		// one-way flow reads nothing back, so without it the silent side would reap a healthy, actively-used
		// connection. It deliberately does NOT stamp b.lastRxData: a successful write means only that our own
		// socket accepted the bytes, so suppressing the keepalive on it hides a receive-direction blackhole.
		cf.conn.SetReadDeadline(time.Now().Add(b.idle))
	}
}

// diagLoop (client) emits a low-rate heartbeat of the process goroutine count, so a carrier session that
// is retired on rotation but not fully reaped shows up in journald as a climbing number — a measurable
// trend instead of an "it worked for hours then rotation stopped" report. Never touches the data path.
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

// keepaliveLoop (client) pings the server over the live connection so idle
// tunnels do not get reaped by stateful middleboxes. In all modes the period is
// jittered so it does not emit on a fixed clock.
func (b *TCP) keepaliveLoop() {
	for {
		// Jitter in ALL modes: a fixed keepalive clock is a passive timing
		// fingerprint even without obfs framing.
		select {
		case <-b.closeCh:
			return
		case <-time.After(keepaliveInterval(b.keepalive, b.psk)):
			// Opportunistic: skip the keepalive when real data ARRIVED within the last period — that frame
			// already proved the peer is alive and answering. Outbound data must not count (see recentData).
			// The node's tun probe is ordinary inbound data here, and it runs far more often than this
			// timer, so on a tunnel whose agent is up this ping is almost always the one that is skipped.
			if cf := b.cur.Load(); cf != nil && !b.recentData() {
				if ok, err := b.pingOne(cf); !ok {
					if err == errPingTimeout {
						log.Printf("core/tcp: %d keepalive pings unanswered — dropping stale connection", pingLossThreshold)
					}
					b.onConnErr(cf, err)
				}
			}
		}
	}
}

// pingOne sends one keepalive ping on cf and advances its ping-loss counter. It returns ok=false
// when the connection should be dropped: a write error (returned as err) or too many unanswered
// pings (errPingTimeout). A silently black-holed connection trips the latter well before the idle
// deadline. readLoop resets the counter on any inbound frame.
func (b *TCP) pingOne(cf *connFramer) (ok bool, err error) {
	// Test the count BEFORE this send. Testing it after drops the connection on the ping just written,
	// which has had no time at all to be answered — so a threshold of N gave N-1 real chances, and N=1
	// closed a healthy connection the instant its first ping left.
	if cf.unanswered.Load() >= pingLossThreshold {
		return false, errPingTimeout
	}
	if err := cf.writeFrame(typePing, nil); err != nil {
		return false, err
	}
	cf.unanswered.Add(1)
	return true, nil
}

// recentData reports whether a real DATA frame ARRIVED within the last keepalive period; when one did,
// the standalone ping is redundant and an active tunnel emits no periodic beacon. The base keepalive
// (not the jittered interval) is the window, and a connection that has received nothing yet keeps the
// normal keepalive. Only INBOUND data may suppress the ping — see the b.lastRxData field.
func (b *TCP) recentData() bool {
	last := b.lastRxData.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) < b.keepalive
}

// sleep waits d or returns true if Close fired during the wait.
func (b *TCP) sleep(d time.Duration) bool {
	select {
	case <-b.closeCh:
		return true
	case <-time.After(d):
		return false
	}
}
