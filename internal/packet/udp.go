// Package packet implements the core carrier: raw L3 IP packets read from a TUN device, framed
// one-per-datagram, optionally AEAD-sealed, and shipped over UDP to the peer, which writes them into
// its own TUN.
//
// Wire format (one UDP datagram = one frame):
//
//	[0] magic = 0xB1               (legacy framing only; obfs framing has no magic)
//	[1] type  = 0 data | 1 ping | 2 pong
//	[2:] payload — sealed when crypto is on, raw when off
//
// With crypto on, the two ends first run an ephemeral X25519 handshake (crypto.SessionSealer) and data
// flows only once that session exists, so a captured old-session frame opens under nothing and can
// neither rebind the peer nor inject a packet. Handshake messages are demuxed from data by trial: a
// datagram that does not AEAD-open under the current session is tried as a PSK-MAC-authenticated
// handshake message, and anything that is neither is dropped in silence. Clear mode has neither.
package packet

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	magic byte = 0xB1

	typeData byte = 0
	typePing byte = 1
	typePong byte = 2

	maxDatagram = 65535
)

// Sealer is the subset of crypto.Sealer core needs. Open returns the authenticated (session, seq) pair
// from the nonce so the carrier can reject replays before acting on a frame. aad carries the cleartext
// frame header (the type byte in legacy framing) so it is authenticated and cannot be flipped on the
// wire; obfs framing folds the type into the plaintext and passes nil.
type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (session uint64, seq uint64, pt []byte, err error)
}

// sealerBox lets a *crypto.Sealer live in an atomic.Pointer.
type sealerBox struct{ s Sealer }

// stagedBox is one server-side staged (pending) session: its sealer plus its own replay guard, adopted
// verbatim on promotion. A BOUNDED SET of these (maxStaged) replaces a single pending slot, so a
// replayed init can no longer evict a legit client's staged session by overwriting one slot. Shared by
// udp/raw/flux; touched only on the single receive goroutine, so it needs no lock.
type stagedBox struct {
	box *sealerBox
	rp  replayGuard
}

// maxStaged bounds the staged-candidate set (aligned with the handshake-cache size). Small: the set
// only ever holds one entry on the normal path, and every non-live frame trial-opens against each
// entry, so the bound also caps that per-packet work.
const maxStaged = 8

// stageSession appends a freshly derived session to the bounded staged set, evicting the OLDEST first
// (FIFO) when full so the just-staged (newest, legit) candidate always survives.
func stageSession(set []*stagedBox, s Sealer) []*stagedBox {
	if len(set) >= maxStaged {
		set = set[1:]
	}
	return append(set, &stagedBox{box: &sealerBox{s: s}})
}

// UDP carries L3 packets between a TUN device and a UDP peer.
type UDP struct {
	// conn is the live socket. It is an atomic pointer (not a plain *net.UDPConn) because a source-IP
	// rotation rebinds it: rotateSourceUDP opens a fresh socket on the new source IP, swaps it in, and
	// closes the old one. rebindGen is bumped on every deliberate rebind so the receive loop can tell a
	// rotation-induced ReadFromUDP error (reload the new conn and keep going) from a real socket death.
	conn      atomic.Pointer[net.UDPConn]
	rebindGen atomic.Int64
	rebindMu  sync.Mutex // serializes rebindSourceTo so a proactive rotation and a pin-poll adopt can't race the swap (double-close / socket leak)
	// Server-side listen sockets. A pooled server binds ONE socket per selected pool IP, so the reply
	// leaves from the SAME IP the client dialed. replyConn is the socket an AUTHENTICATED frame last
	// arrived on — committed only where the peer is learned, so a stray or hostile datagram to another
	// pool IP cannot hijack the reply source. rxMu funnels the N read loops into one receiver.
	srvConns  []*net.UDPConn
	replyConn atomic.Pointer[net.UDPConn]
	rxConn    atomic.Pointer[net.UDPConn]
	rxMu      sync.Mutex
	dev       *tun.Device
	keepalive time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	isClient  bool

	peer    atomic.Pointer[net.UDPAddr]      // current known peer (server learns it)
	session atomic.Pointer[sealerBox]        // negotiated session sealer (nil until handshake / clear mode)
	rp      replayGuard                      // driven only by the single receive goroutine (netToTun on the client; serverReadLoop under rxMu on the server)
	sendErr sendErrLog                       // throttled data-plane send-failure logging (see sendlog.go)
	staged  []*stagedBox                     // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache initCache                        // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci      atomic.Pointer[crypto.Ephemeral] // client's current handshake ephemeral
	lastRx  atomic.Int64                     // unix-nano of the last authenticated frame (client staleness)
	hbRx    atomic.Int64                     // unix-nano of the last REAL inbound frame — feeds the status heartbeat; 0 until the peer answers
	// peerAnswered gates the clear-mode heal: it is set when the CURRENT peer replies and cleared on
	// every peer rotation, so success() only clears a burn on an endpoint that has actually replied
	// SINCE we (re)pointed at it — never a false heal on a just-jumped-to (unproven) endpoint.
	peerAnswered atomic.Bool

	fecEnc *fecEncoder                 // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                 // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxAddr atomic.Pointer[net.UDPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	closeCh   chan struct{}
	closeOnce sync.Once
	wake      chan struct{} // client-only: cuts clientLoop's sleep short once the session is cleared elsewhere (wakeLoop)

	st      *coreStatus         // client-only: precise self-heal event ring written to the status file (nil = off)
	pp      *PeerPool           // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	poolIPs map[string]struct{} // client-only: the destination pool's IPs (4-byte keys), so a frame from the endpoint we just left is not mistaken for proof that the new one is alive; set once before Run
	sp      *PeerPool           // client-only: source-IP rotation pool (nil = fixed source; rebinds the socket on rotate)
}

// SetPeerPool (client, direct transports) wires a destination-IP rotation pool: when the current
// peer looks dead (its handshake never completes) the client burns it and re-points at the next
// live endpoint, and a proactive timer also rotates. nil / single-endpoint pool = no rotation. main
// wires it via the shared SetPeerPool type assertion. Call before Run().
func (b *UDP) SetPeerPool(pp *PeerPool) {
	if b.isClient {
		b.pp = pp
		if pp != nil {
			b.poolIPs = buildSrcAllow(pp.all()) // see provenFrom: tells "the endpoint we left" apart from "an unattributable source"
		}
	}
}

// peerFailThreshold is how many ~1s handshake retransmits with no session go by before the client
// gives up on the session it is holding and drops back to a fresh handshake (crypto on). It no longer
// rotates: which endpoint to be on is the node probe's call, and this is only about how long to keep
// re-initing before starting over. Long enough to ride out a slow handshake or brief loss.
const peerFailThreshold = 12

// handshakeRetransmit is the base gap between handshake inits, and between probes of an endpoint a
// timed rotation jumped to. Faster than keepalive on purpose: nothing is established yet.
const handshakeRetransmit = time.Second

// handshakeRetransmitWait is that gap with jitter. An unestablished datagram carrier sends on this
// clock and nothing else, so a fixed value is a 1 Hz beacon a passive observer can lock onto with no
// payload analysis at all — and it runs for exactly as long as the tunnel cannot come up, which is
// when a filtered path is most worth fingerprinting.
func handshakeRetransmitWait() time.Duration { return jitterFrac(handshakeRetransmit) }

// wakeLoop nudges a datagram client loop out of the sleep it is in. The loop already picks the short
// handshakeRetransmitWait when there is no session — but it picks BEFORE it sleeps, so a session another
// goroutine clears mid-sleep goes unnoticed until the sleep ends, putting a whole keepalive between a
// failover (or an operator's jump) and its re-handshake. Buffered to one and non-blocking: the loop
// needs to know THAT something changed, never how often. Nil-safe.
func wakeLoop(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// pinFailRelease is how many proven-dead rounds a manual pin absorbs before it auto-releases, so the
// tunnel recovers instead of freezing on a blocked endpoint indefinitely. A round is now one
// node-driven failover ask — the node has already confirmed the silence over two sweeps before it asks,
// so two of them is a deliberate second opinion, not a retry count.
const pinFailRelease = 2

// rotatePeerUDP points the client at the next pool endpoint: burn+advance (proactive=false) or a timed
// rotate (proactive=true). No-op when the pool did not move. A TIMED rotation keeps the AEAD session,
// so not one packet is dropped — every pool endpoint is an address of the SAME server process and the
// session is independent of the address. A FAILOVER clears it: that endpoint stopped answering.
func (b *UDP) rotatePeerUDP(proactive bool) {
	if b.pp == nil {
		return
	}
	addr, moved := b.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil || ua == nil {
		return
	}
	b.peer.Store(ua)
	if !proactive {
		b.session.Store(nil) // the endpoint failed — force a fresh handshake to the next one
		b.ci.Store(nil)
	}
	// Give the jumped-to endpoint a FRESH staleness window and mark it unproven, so sessionStale measures
	// THIS endpoint. Without the reset, a PROACTIVE rotation onto a dead endpoint never fires clear-mode
	// failover — lastRx stays recent from the old one — and the tunnel strands on the blackhole.
	b.lastRx.Store(time.Now().UnixNano())
	b.peerAnswered.Store(false)
	log.Printf("core/udp: rotated destination to %s", addr)
	// Refresh the live-carrier descriptor so the status file's "active" field tracks the NEW destination
	// instead of staying frozen at the initial peer. Only the DESTINATION path refreshes active; the
	// source path leaves it, since "active" names the destination.
	b.st.setActive("udp · " + ua.String())
	if proactive {
		// Seamless: no session was cleared, so there is no re-handshake and nothing for a "reconnect" to pair
		// with. event() records the jump WITHOUT arming wasDown — down() here surfaces every timed rotation
		// in the panel as a drop plus a self-heal.
		b.st.event("down", "peer-rotate", "ip:"+addr)
		return
	}
	b.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
	// Last, so every field the loop reads is settled before it can look. This runs on the pin poller
	// (only a failover reaches it); the timed rotation above keeps its session and returns first.
	wakeLoop(b.wake)
}

// SetSourcePool (client) wires a source-IP rotation pool: the client cycles the local IP it sends FROM.
// Unlike raw/flux (which stamp the source per packet), udp owns a kernel socket, so a rotation REBINDS
// it. The AEAD session is independent of the address, so it survives and the server just relearns the
// peer from the next authenticated frame. nil / single-endpoint = fixed source. Call before Run().
func (b *UDP) SetSourcePool(sp *PeerPool) {
	if !b.isClient {
		return
	}
	b.sp = sp
	// Bind the initial socket to the pool's first source so the client egresses from SrcIPs[0]
	// immediately (matching the pool's cur=0), instead of the OS-default source until the first
	// rotation — which on a failover-only pool (rotate=0) would otherwise never happen. Called before
	// Run(), so there is no receive loop yet: a plain swap (no rebindGen dance) is safe here.
	if sp != nil {
		host := sp.current()
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
			if err != nil {
				// Loud, like the rotation twin below: silence here left the client on the kernel's
				// default source with the operator's chosen egress IP quietly unused — and with a lone
				// src_ip and rotate=0 the pool never moves, so it is never retried either.
				log.Printf("core/udp: initial source bind to %s failed: %v", host, err)
				// ...and BURN it, which loudness alone never did. The socket stayed on the kernel default while
				// the pool went on calling this entry Active, so the panel named a source the datagram path had
				// never adopted. failUnusable burns unconditionally: the kernel's refusal is not the
				// remote-reachability question auto-burn is a policy for.
				b.sp.failUnusable()
			}
			if err == nil {
				applyConnSockBuf(nc)
				old := b.conn.Load()
				b.conn.Store(nc)
				if old != nil {
					_ = old.Close()
				}
			}
		}
	}
}

// rotateSourceUDP rebinds the socket onto the next source-pool IP. It does NOT touch the session (the
// source is independent of the AEAD keys), so no re-handshake: the client keeps sending under the same
// session from the new local address and the server follows. No-op when the pool did not move or the
// new socket can't bind (e.g. the IP isn't local) — the old socket stays live.
func (b *UDP) rotateSourceUDP(proactive bool) {
	if b.sp == nil {
		return
	}
	prev := b.sp.current() // the source the socket is on now — fall back here if the new one can't bind
	addr, moved := b.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: rotated source to %s", host)
		// A source rebind keeps the SAME AEAD session alive (no re-handshake), so there is no matching
		// reconnect. Use event() not down(): log the rotation but do NOT arm wasDown (which would leave a
		// phantom pending recovery that a later unrelated re-handshake would mis-pair). Carry the new IP.
		b.st.event("down", "src-rotate", "ip:"+host)
		return
	}
	// The pool advanced onto a source that will not bind on this host (the IP was removed from the
	// interface but not from the pool). The socket never left prev, so undo the pool MOVE — otherwise the
	// status file names a source the datagram path never adopted. Only the move: prev's health is left
	// exactly as it was, since nothing here measured it. No src-rotate event either — nothing moved.
	b.sp.rejectCandidate(prev)
}

// rebindSourceTo opens a fresh socket on the given source IP (bare or ip:port) and swaps it in for the
// live one, returning the bound host and whether it happened. Shared by proactive/failover rotation and
// the operator source pin. No-op / false when the IP can't be parsed or bound (the old socket stays live).
func (b *UDP) rebindSourceTo(addr string) (string, bool) {
	host := addr
	if h, _, e := net.SplitHostPort(addr); e == nil { // tolerate an accidental ip:port
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	b.rebindMu.Lock() // serialize the load/store/gen-bump/close so a concurrent rebind can't leak or double-close
	defer b.rebindMu.Unlock()
	nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip}) // fresh socket on the new source (ephemeral port)
	if err != nil {
		log.Printf("core/udp: source rebind to %s failed: %v", host, err)
		return "", false
	}
	applyConnSockBuf(nc)
	old := b.conn.Load()
	// Order matters (netToTun loads gen THEN conn): store the new conn BEFORE bumping the gen. Then any
	// reader that still loaded the OLD conn must have sampled its gen BEFORE this bump (Go atomics are
	// sequentially consistent), so its post-error re-check sees the bumped gen and continues instead of
	// misreading the deliberate swap as a socket death. Bumping before the store reopens that race.
	b.conn.Store(nc)
	b.rebindGen.Add(1)
	_ = old.Close() // unblocks netToTun's ReadFromUDP; it reloads nc via rebindGen and continues
	return host, true
}

// adoptPeerUDP re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (b *UDP) adoptPeerUDP() {
	if b.pp == nil {
		return
	}
	addr := b.pp.current()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil || ua == nil {
		return
	}
	b.peer.Store(ua)
	b.session.Store(nil)
	b.ci.Store(nil)
	// The same two resets rotatePeerUDP performs, for the same reason: a pin is a jump to an endpoint that
	// has proven NOTHING yet. Without them, clear mode (no handshake to gate on) runs the heal for the
	// newly pinned endpoint on the very next tick — clearing its burn, emitting a false heal and releasing
	// the pin before it landed — and its dead window is measured from a frame it never sent.
	b.lastRx.Store(time.Now().UnixNano())
	b.peerAnswered.Store(false)
	log.Printf("core/udp: pinned destination to %s", addr)
	// "Make this active" is a deliberate operator jump — logged SILENTLY like the ws edge pool: only the
	// active endpoint changes, no down/up in the event ring. The session clear above still forces the
	// re-handshake onto the pinned peer; setActive keeps "active" tracking it (see rotatePeerUDP). We do NOT
	// emit down("peer-pin") — that armed a paired reconnect and surfaced a manual jump as a rotation event.
	b.st.setActive("udp · " + ua.String())
	wakeLoop(b.wake) // the session is gone; do not make the operator's jump wait out a keepalive
}

// adoptSourceUDP rebinds the socket onto the pool's CURRENT source (an operator source pin). Safe from
// the pin-poll goroutine: a pin freezes rotation (rotationController.pinned), so rotateSourceUDP cannot
// be rebinding concurrently.
func (b *UDP) adoptSourceUDP() {
	if b.sp == nil {
		return
	}
	addr := b.sp.current()
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: pinned source to %s", host)
		// THIS is the landing. A source swap keeps the AEAD session, so no handshake follows that anyone
		// could read one off, and the success path that releases a pin only runs when something failed
		// first — so on a healthy tunnel the operator's jump would sit "in progress" indefinitely.
		b.sp.pinLandedOn(addr)
		// Silent, like the ws edge pool: a manual source "make this active" changes only the active source
		// (the source pool's own status file reflects it). The session survives, so there's nothing to
		// reconnect and no event is emitted — we no longer log a src-pin here.
		return
	}
	// The rebind failed, so the socket never left the old source and the jump did NOT land. Leaving the pin
	// live holds indefinitely forcing a source the host cannot bind, and the ordinary success path then
	// releases it as though it HAD landed. End the jump — it is momentary, not a lock — and burn the entry,
	// in that order, since failWith refuses to touch a pinned one. Unconditional, like adoptableSource.
	if b.sp.pinCannotLand(addr) {
		log.Printf("core/udp: manual jump to source %s abandoned — that IP will not bind on this host", addr)
	}
	b.sp.failUnusable()
}

// probeAllPools pulls every suspect/dead endpoint's retest forward on both of a carrier's pools (the
// "probe now" control). Shared by udp/raw/flux, which differ only by which struct fields hold the pools.
func probeAllPools(pp, sp *PeerPool) {
	if pp != nil {
		pp.probeAllNow()
	}
	if sp != nil {
		sp.probeAllNow()
	}
}

// runPinPoll is the 1s ticker that applies operator pins for a datagram carrier: identical across
// udp/raw/flux, which inject their own close channel and adopt-peer/adopt-source callbacks.
func runPinPoll(rc *rotationController, closeCh <-chan struct{}, adoptPeer, adoptSource func(),
	rotDst, rotSrc func(proactive bool), ev func(kind, code, detail string)) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-t.C:
			rc.pollPins(adoptPeer, adoptSource, rotDst, rotSrc, ev)
		}
	}
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (b *UDP) ProbeAllNow() {
	probeAllPools(b.pp, b.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin. Runs until Close.
func (b *UDP) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, b.closeCh, b.adoptPeerUDP, b.adoptSourceUDP, b.rotatePeerUDP, b.rotateSourceUDP, b.st.event)
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (b *UDP) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := b.peer.Load(); p != nil {
		peer = p.String()
	}
	b.st = newCoreStatus(path, "udp · "+peer, roleOf(b.isClient))
}

// deadWin is the session-stale window this carrier enforces, and the period the status heartbeat is
// paced off so an idle tunnel republishes well inside it.
func (b *UDP) deadWin() time.Duration { return deadWindow(b.keepalive) }

// sessionStale reports that the client has heard nothing it could authenticate for long enough that the
// peer has most likely restarted with a fresh session, so the client drops its now-useless session and
// re-handshakes. Without it a SERVER restart wedges the tunnel: the client keeps pinging under a key the
// fresh server cannot open. A false positive costs one harmless re-handshake. Crypto only.
func (b *UDP) sessionStale() bool { return staleSince(b.lastRx.Load(), b.deadWin()) }

// markRx stamps a genuine inbound frame, advancing BOTH the failover clock (lastRx) and the liveness
// heartbeat (hbRx). hbRx is set ONLY here — on proven inbound — so hb reads 0 until the peer actually
// answers, which keeps a still-connecting tunnel yellow instead of a false green. Seeds that only
// re-baseline the failover clock (connect, rotation) call lastRx.Store directly and must not come here.
func (b *UDP) markRx() {
	now := time.Now().UnixNano()
	b.lastRx.Store(now)
	b.hbRx.Store(now)
}

// provenFrom marks the CURRENT destination as answering. A timed rotation keeps the session, so for
// about one RTT after a jump the endpoint we LEFT is still answering; those frames are ours and are
// delivered, but counting them as proof is what lets a blocked IP hide behind the one it replaced. A
// frame from an address that is not another pool endpoint is unattributable and still counts.
func (b *UDP) provenFrom(ip net.IP) {
	if ip != nil && len(b.poolIPs) > 0 {
		if p := b.peer.Load(); p != nil && !p.IP.Equal(ip) {
			if v4 := ip.To4(); v4 != nil {
				if _, other := b.poolIPs[string(v4)]; other {
					return
				}
			}
		}
	}
	b.peerAnswered.Store(true)
}

// Dial (client role) binds an ephemeral UDP socket and targets peerAddr.
func Dial(peerAddr string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*UDP, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil) // ephemeral local port
	if err != nil {
		return nil, err
	}
	applyConnSockBuf(conn)
	b := &UDP{dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, isClient: true,
		closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.conn.Store(conn)
	b.peer.Store(ra)
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// Listen (server role) binds one socket per listen address and waits to learn the peer. A non-pooled
// server passes a single address; a pooled server passes one "ip:port" per selected pool IP, so only
// those IPs listen (not 0.0.0.0) and each reply leaves from the IP the client actually dialed.
func Listen(listenAddrs []string, dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int) (*UDP, error) {
	b := &UDP{dev: dev, keepalive: keepalive, obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, closeCh: make(chan struct{})}
	for _, listenAddr := range listenAddrs {
		la, err := net.ResolveUDPAddr("udp", listenAddr)
		if err == nil {
			var conn *net.UDPConn
			conn, err = net.ListenUDP("udp", la)
			if err == nil {
				applyConnSockBuf(conn)
				b.srvConns = append(b.srvConns, conn)
				continue
			}
		}
		for _, c := range b.srvConns { // a later bind failed — release the ones already bound
			_ = c.Close()
		}
		return nil, err
	}
	if len(b.srvConns) == 0 {
		return nil, errors.New("udp listen: no listen address")
	}
	b.replyConn.Store(b.srvConns[0]) // default reply socket until the client is first heard
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

// serverReadLoop reads one server listen socket. All listen sockets funnel through rxMu into the single
// receiver contract the crypto/replay/handshake-cache/FEC path assumes. The socket is stashed as the
// reply CANDIDATE and promoted only when a frame AUTHENTICATES and the peer is (re)learned, so an
// unauthenticated datagram to another pool IP cannot hijack the reply source.
func (b *UDP) serverReadLoop(c *net.UDPConn) error {
	buf := make([]byte, maxDatagram)
	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		b.rxMu.Lock()
		b.rxConn.Store(c) // candidate; learnPeer promotes it to replyConn after the frame authenticates
		if b.fecDec != nil {
			b.rxAddr.Store(addr)
			b.fecDec.input(buf[:n])
		} else {
			b.deliver(buf[:n], addr)
		}
		b.rxMu.Unlock()
	}
}

// learnPeer records the authenticated client's source address and, on a server, promotes the socket the
// frame arrived on to the reply socket, so a pooled server replies from the exact IP the client dialed.
// Called ONLY after a frame authenticates, or in clear mode. On the client the reply socket is the
// single dial socket, so replyConn is left untouched.
func (b *UDP) learnPeer(addr *net.UDPAddr) {
	// Commit the reply socket BEFORE publishing the peer: tunToNet gates its downstream send on
	// peer!=nil and then reads replyConn, so ordering the (sequentially-consistent) atomic stores this
	// way guarantees a sender that sees the new peer also sees the matching reply socket — never a stale
	// srvConns[0] for one packet on the very first authenticated frame.
	if !b.isClient {
		if c := b.rxConn.Load(); c != nil {
			b.replyConn.Store(c)
		}
	}
	b.peer.Store(addr)
}

// sendConn is the socket for an UNSOLICITED send (downstream data from tunToNet, FEC flush): the client's
// single socket, or (server) replyConn — the socket an authenticated frame was last received on, so a
// pooled server's downstream leaves from the exact IP the client dialed.
func (b *UDP) sendConn() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	return b.replyConn.Load()
}

// hostOnly returns the host part of an "ip:port", or s unchanged if it has none. Portable, beside
// its portable caller below, for the same reason buildSrcAllow is.
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}

// parseIP4 parses s as an IPv4 address, returning nil for anything else (including a valid IPv6).
func parseIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// adoptableSource resolves a source-pool entry to an IPv4 this host can actually SEND FROM, for the
// carriers that STAMP the source into a crafted header instead of binding a socket to it — where an
// unusable source is a silent blackout, since sendViaConn will not fall back to the kernel source with
// the L4 checksum already computed over the pinned one. nil = do not adopt; the caller owns the burn.
func adoptableSource(tag string, sp *PeerPool, addr string, warned *sync.Map) net.IP {
	ip := parseIP4(hostOnly(addr))
	if ip != nil && canBindSource(ip) {
		return ip
	}
	if _, dup := warned.LoadOrStore(addr, struct{}{}); !dup {
		if ip == nil {
			log.Printf("core/%s: source %q is not a usable IPv4 address — leaving the kernel to pick the source", tag, addr)
		} else {
			log.Printf("core/%s: source IP %s is not configured on this host — leaving the kernel to pick the source", tag, ip)
		}
	}
	// An operator jump aimed HERE is over: we have just proven the IP cannot be used, and a jump is a
	// momentary move within the rotation, not a lock. Ending it also unblocks the caller's burn —
	// fail() refuses to touch a pinned entry (the same reasoning as dropUnusableSource).
	if sp != nil && sp.pinCannotLand(addr) {
		log.Printf("core/%s: manual jump to source %s abandoned — that IP is not configured on this host", tag, addr)
	}
	return nil
}

// buildSrcAllow builds the server-side source-IP admit set from a pool's source IPs, keyed by bare
// 4-byte IPv4. Shared by udp, raw and flux. It lives in a PORTABLE file because portable udp.go calls
// it: behind a //go:build linux tag the package fails to type-check for any other GOOS.
func buildSrcAllow(ips []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, s := range ips {
		if ip := parseIP4(hostOnly(s)); ip != nil {
			m[string(ip.To4())] = struct{}{}
		}
	}
	return m
}

// replySock is the socket for a SOLICITED reply (a handshake response or a pong, sent while processing
// an inbound packet under rxMu): the client's single socket, or (server) rxConn — the socket THIS packet
// arrived on. Using rxConn rather than replyConn means a handshake response leaves from the exact IP the
// client dialed even before any data frame has authenticated, while a hostile init only echoes back.
func (b *UDP) replySock() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	if c := b.rxConn.Load(); c != nil {
		return c
	}
	return b.replyConn.Load()
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards emit to
// the current peer; recovered frames re-enter the normal receive path with the source
// of the packet that completed their block.
func (b *UDP) initFec(fec bool, fecData, fecParity int) {
	b.fecEnc, b.fecDec = newFecPair(fec, fecData, fecParity, "udp",
		func(pkt []byte) {
			if p := b.peer.Load(); p != nil {
				if c := b.sendConn(); c != nil {
					// With FEC on, tunToNet hands every frame to the encoder and never writes itself, so
					// this callback IS the data plane — swallowing here loses the whole carrier in silence.
					if _, err := c.WriteToUDP(pkt, p); err != nil {
						b.sendErr.note("udp/fec", err)
					}
				}
			}
		},
		func(frame []byte) { b.deliver(frame, b.rxAddr.Load()) })
}

// Run blocks until one of the loops fails (e.g. a socket or the device closes). The client reads its one
// socket; a server reads each of its listen sockets (one per pool IP) in its own loop.
func (b *UDP) Run() error {
	errc := make(chan error, 2+len(b.srvConns))
	go func() { errc <- b.tunToNet() }()
	// BOTH ends publish. The server's own lastRx proves the CLIENT->SERVER direction — a fact only that
	// end can see — and without it a server had no liveness signal at all and fell back to probing.
	dw := int64(b.deadWin().Seconds())
	b.st.setDW(dw)                             // publish it so the reader ages hb against it...
	go heartbeat(b.st, &b.hbRx, b.closeCh, dw) // ...and pace the republish off it, so an idle tunnel reads live, not half-open
	if b.isClient {
		go func() { errc <- b.netToTun() }()
		go b.clientLoop()
	} else {
		for _, c := range b.srvConns {
			c := c
			go func() { errc <- b.serverReadLoop(c) }()
		}
	}
	return <-errc
}

// Close tears down the socket(s) (which unblocks the loops) and stops the client loop. Safe to call more
// than once.
func (b *UDP) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	if b.fecEnc != nil {
		b.fecEnc.Close() // stop the FEC flush timer before the socket goes away
	}
	if b.isClient {
		if c := b.conn.Load(); c != nil {
			return c.Close()
		}
		return nil
	}
	var err error
	for _, c := range b.srvConns {
		if e := c.Close(); e != nil {
			err = e
		}
	}
	return err
}

func (b *UDP) sealer() Sealer {
	if box := b.session.Load(); box != nil {
		return box.s
	}
	return nil
}

// frame builds one datagram for typ/payload using the current session sealer
// (or clear framing when crypto is off / no session yet).
func (b *UDP) frame(typ byte, payload []byte) ([]byte, error) {
	return sealBody(b.sealer(), b.obfs, typ, payload, padMaxFor(typ))
}

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer. Packets
// read before a session exists (crypto on, handshake not yet complete) are
// dropped; the peer retransmits at L4.
func (b *UDP) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := b.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet; drop
		}
		if b.cryptoOn && b.sealer() == nil {
			continue // handshake not finished yet; drop (L4 will retransmit)
		}
		frame, err := b.frame(typeData, buf[:n])
		if err != nil {
			log.Printf("core: seal error: %v", err)
			continue
		}
		if b.fecEnc != nil {
			b.fecEnc.addData(frame) // buffered into an RS block; shards go out via the emit callback
			continue
		}
		if c := b.sendConn(); c != nil {
			if _, err := c.WriteToUDP(frame, peer); err != nil {
				// Throttled: a failing socket fails at packet rate, and an unthrottled line here writes
				// thousands a second into the journal, which hides the fault as effectively as silence.
				b.sendErr.note("udp", err)
			}
		}
	}
}

// netToTun receives datagrams, authenticates them, rejects replays, updates the
// known peer, and writes data frames into the TUN. Datagrams that do not open
// under the current session are tried as handshake messages.
func (b *UDP) netToTun() error {
	buf := make([]byte, maxDatagram)
	for {
		gen := b.rebindGen.Load()
		n, addr, err := b.conn.Load().ReadFromUDP(buf)
		if err != nil {
			// A source rotation closes the old socket out from under this read. Distinguish that
			// deliberate swap (gen advanced) — reload the new socket and keep going — from a genuine
			// socket death (gen unchanged), which ends the loop as before.
			if b.rebindGen.Load() != gen {
				continue
			}
			return err
		}
		if b.fecDec != nil {
			// netToTun is the sole reader, so rxAddr is stable for the whole input()
			// call (the decoder delivers recovered frames synchronously within it).
			b.rxAddr.Store(addr)
			b.fecDec.input(buf[:n])
			continue
		}
		b.deliver(buf[:n], addr)
	}
}

// deliver dispatches one received frame (already de-FEC'd): authenticated data in
// crypto mode, or unauthenticated legacy framing in clear mode.
func (b *UDP) deliver(pkt []byte, addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	if b.cryptoOn {
		b.handleCrypto(pkt, addr)
		return
	}
	if len(pkt) < 2 || pkt[0] != magic {
		return
	}
	b.markRx()            // the peer is answering (clear mode has no session to prove it)
	b.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
	if b.pp == nil {      // a pooled client owns its peer (mirror the crypto path); a server always learns it
		b.learnPeer(addr)
	}
	b.dispatch(pkt[1], iff(pkt[1] == typeData, pkt[2:], nil), addr)
}

// sealBody builds one outbound frame for typ/payload: obfs, crypto (magic+type+sealed), or clear
// (magic+type+payload). The send-side mirror of openFrame; shared by udp/raw/flux, which each pass their
// own padMax (padMaxFor for udp/raw, fluxPadMax for flux — both pure reads, so evaluating eagerly at the
// call site is harmless even when obfs is off and padMax goes unused).
func sealBody(s Sealer, obfs bool, typ byte, payload []byte, padMax int) ([]byte, error) {
	if obfs {
		return obfsSeal(s, typ, payload, padMax)
	}
	if s != nil {
		sealed, err := s.Seal(payload, []byte{typ}) // authenticate the type byte
		if err != nil {
			return nil, err
		}
		out := make([]byte, 2+len(sealed))
		out[0], out[1] = magic, typ
		copy(out[2:], sealed)
		return out, nil
	}
	out := make([]byte, 2+len(payload))
	out[0], out[1] = magic, typ
	copy(out[2:], payload)
	return out, nil
}

// openFrame is the shared receive-side frame opener for the datagram carriers (udp/raw/flux): obfs
// path when obfs is on, else parse the magic/type header and authenticate the type byte via the
// sealer. The three carriers' openWith methods differ only by the obfs field, so they delegate here.
func openFrame(s Sealer, data []byte, obfs bool) (typ byte, session, seq uint64, payload []byte, oerr error) {
	if obfs {
		return obfsOpen(s, data)
	}
	if len(data) >= 2 && data[0] == magic {
		typ = data[1]
		session, seq, payload, oerr = s.Open(data[2:], []byte{typ})
		return
	}
	return 0, 0, 0, nil, errBadFrame
}

// openWith tries to open one datagram under a specific session sealer, returning the
// authenticated frame. It touches no session/replay state, so a frame can safely be tried
// against both the live and a pending session.
func (b *UDP) openWith(s Sealer, pkt []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, pkt, b.obfs)
}

// handleCrypto is the crypto-on receive path: try the frame as data under the current
// session; failing that, under a pending session staged by a recent init (promoting it if
// it opens); failing that, as a handshake message.
func (b *UDP) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		if typ, session, seq, payload, oerr := b.openWith(s, pkt); oerr == nil && b.rp.ok(session, seq) {
			// authenticated, fresh frame -> now safe to (re)learn the peer address
			b.markRx()            // the session is answering
			b.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
			// The DESTINATION pool owns the client's peer: don't rebind it from a reply's source, so a
			// client's own rotation isn't silently pulled off the endpoint its pool is driving. Servers
			// (pp==nil) learn the client here — which lets them follow a client's SOURCE rotation and, on
			// a pooled server, promote this socket as the reply source (the IP the client actually dialed).
			if b.pp == nil {
				b.learnPeer(addr)
			}
			b.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent init.
	// Only a frame that actually opens under a candidate promotes it, so a replayed init — which stages a
	// session an attacker cannot produce a frame for — never tears down the live session or resets its
	// replay window. The live session is tried first, so an established tunnel never reaches this loop.
	for _, st := range b.staged {
		if typ, session, seq, payload, oerr := b.openWith(st.box.s, pkt); oerr == nil && st.rp.ok(session, seq) {
			b.session.Store(st.box)
			b.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
			b.rp = st.rp
			b.staged = nil
			b.markRx() // a pending session promoted -> genuine inbound
			b.learnPeer(addr)
			b.dispatch(typ, payload, addr)
			return
		}
	}
	b.tryHandshake(pkt, addr)
}

// tryHandshake demuxes a datagram that did not open as data. On the server an
// init starts a fresh session; on the client a resp completes ours.
func (b *UDP) tryHandshake(pkt []byte, addr *net.UDPAddr) {
	if b.isClient {
		ci := b.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(b.psk, ci.Pub, pkt)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(b.cipher, b.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		b.rp = replayGuard{}
		b.session.Store(&sealerBox{s: s})
		b.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		b.ci.Store(nil)
		b.markRx()              // server RESP arrived: genuine inbound (green on a real connect)
		b.provenFrom(addr.IP)   // ...and it answered the endpoint we are addressing
		b.st.reconnected("udp") // recovery after a self-heal (nil-safe; silent on first connect)
		return
	}
	// server: authenticate an init, reply, and install the fresh session. Compute-DoS mitigation: an
	// attacker replaying captured valid inits at high rate would otherwise force a fresh ECDH+HKDF per
	// packet, so an init matching one we recently answered (while a pending session is current) is served
	// from a small LRU before that crypto. Receive-goroutine-only, like staged, so no locking is needed.
	if len(b.staged) > 0 {
		if resp, ok := b.hsCache.get(pkt); ok {
			b.writeCtrl(resp, addr)
			return
		}
	}
	eInit, err := crypto.ParseInit(b.psk, pkt)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(b.cipher, b.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	// Stage the new session as PENDING rather than swapping it in now. The live session and
	// its replay window stay intact until a frame actually opens under these new keys (see
	// handleCrypto), so a replayed init cannot wedge the tunnel by resetting them. Rebinding
	// the peer is likewise deferred to that first opening frame.
	b.staged = stageSession(b.staged, s)
	if msg2 := crypto.RespMsg(b.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies pkt
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		b.hsCache.put(pkt, msg2)
		b.writeCtrl(msg2, addr)
	}
}

// writeCtrl sends a control/handshake datagram, tagging it passthrough under FEC so the peer's decoder
// forwards it straight through. to may differ from the learned peer (a server's handshake reply). It
// goes out replySock — on a server, the socket THIS inbound packet arrived on, which is the right one
// because writeCtrl is only ever called while processing that packet, under rxMu.
func (b *UDP) writeCtrl(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if c := b.replySock(); c != nil {
		if _, err := c.WriteToUDP(fecTag(b.fecEnc, pkt), to); err != nil {
			// The handshake init/RESP and every keepalive ping/pong leave through here. Losing these
			// silently is worse than losing data: the tunnel never establishes, or its heartbeat
			// freezes, and the panel blames the peer for a fault that is local.
			b.sendErr.note("udp/ctrl", err)
		}
	}
}

func (b *UDP) dispatch(typ byte, payload []byte, addr *net.UDPAddr) {
	switch typ {
	case typePing:
		b.send(typePong, nil, addr)
	case typePong:
		// Nothing to record. A pong proved the endpoint answers, and provenFrom already stamped
		// that off the receive path; the rtt this used to time went to a status field nobody read.
	case typeData:
		if _, err := b.dev.Write(payload); err != nil {
			log.Printf("core: tun write error: %v", err)
		}
	}
}

// clientLoop (client) drives the handshake and keepalives: it (re)sends an init
// until a session exists, then pings on a jittered interval. If the session is
// lost it starts a new handshake.
func (b *UDP) clientLoop() {
	failN := 0        // consecutive handshake retransmits (or unanswered probes) -> the endpoint may be dead
	unproven := false // the current destination has not answered since we jumped to it -> probe at 1s, not keepalive
	rc := newRotationController(b.pp, b.sp)
	if rc.active() {
		go b.pinPollLoop(rc)
	}
	// Seed the staleness baseline NOW (clear mode). Without a baseline, sessionStale() returns false
	// while lastRx==0, so a clear-mode failover-only pool whose FIRST endpoint is dead from the start
	// never fires — it never receives a reply, so lastRx stays 0 and the tunnel strands on the blackhole.
	// Starting the clock at connect makes a from-start-dead endpoint fail over after the dead window.
	b.lastRx.Store(time.Now().UnixNano())
	for {
		if b.cryptoOn && b.sealer() != nil && b.sessionStale() {
			b.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			b.ci.Store(nil)
			log.Print("core: no reply from the peer's session — re-handshaking (peer likely restarted)")
			b.st.down("stale", "udp") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode has no handshake whose failure would drive failover, so use receive-staleness instead:
		// the peer pongs our keepalive pings, so once lastRx ages past the dead window, burn and advance the
		// pool. The baseline is seeded at connect and reset on every rotation, so a fresh tunnel or a
		// just-jumped-to endpoint gets a full window before it can false-fail.
		if !b.cryptoOn && b.sessionStale() {
			// Staleness no longer moves the pool. The node's tun probe owns that decision now, for every
			// carrier alike, and it measures where the payload actually travels instead of inferring from
			// what our own keepalives got back. All that is left here is re-baselining and the event.
			b.lastRx.Store(time.Now().UnixNano()) // fresh window so the next stale is measured from now
			b.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			// The event is NOT conditional on a pool. Every other down/up site here is gated on crypto or on a
			// pool, so clear mode with no rotation pool could write no event at all — while the panel classifies
			// every udp link as "precise" from the transport alone and therefore suppresses its own coarse
			// down/up, leaving the system log empty for the whole life of the tunnel.
			b.st.down("stale", "udp")
		}
		if b.sealer() == nil && b.cryptoOn {
			unproven = false // keep re-initing this endpoint; moving off it is the node's call, not ours
			b.sendInit()
		} else {
			// A manual jump LANDS the moment the endpoint it aimed at answers, and a landed pin has to
			// release AT ONCE: while it is live, both failover and the timed rotation are frozen behind
			// it. Keyed on the address the carrier is REALLY on, like the tcp twin, so a pin aimed
			// somewhere else is never reported as landed.
			if b.pp != nil && b.peerAnswered.Load() {
				if pa := b.peer.Load(); pa != nil {
					b.pp.pinLandedOn(pa.String())
				}
			}
			// No heal here. A frame coming back proves an endpoint answered US, never that the tunnel
			// CARRIES — the node's tun probe owns that verdict and delivers it as cmdOK. All that is
			// left is bookkeeping a live carrier invalidates.
			if b.peerAnswered.Load() {
				rc.success() // live carrier: reset the attribution count and the pin-release count
			}
			// Clear mode has no handshake to fire st.reconnected(), so a self-heal down() would arm wasDown with
			// no matching "up". Pair it on the data-plane recovery instead: reconnected() is a no-op unless a down
			// is pending, so calling it on each answering loop never invents an "up". Ungated on the pool for the
			// same reason the stale down() above is — otherwise the down stays unpaired, a red entry that never resolves.
			if !b.cryptoOn && b.peerAnswered.Load() {
				b.st.reconnected("udp")
			}
			rc.proactive(b.rotatePeerUDP, b.rotateSourceUDP, time.Now()) // moving target on both sides
			// Ping AFTER the rotation, not before: on a rotating tick this frame is the first thing the
			// NEW destination sees, and it is what makes the server promote that socket as its reply
			// source. Sending it first meant the ping went to the endpoint we were leaving and the
			// server did not follow until the next data frame.
			b.send(typePing, nil, b.peer.Load())
			// The endpoint a timed rotation just jumped to has proven NOTHING, and because the session survives,
			// no handshake failure will ever say so. Count unanswered ticks here — AFTER the jump, so the very
			// next wait is already the 1s probe interval — on the same threshold the handshake path uses.
			if unproven = b.cryptoOn && rc.active() && !b.peerAnswered.Load(); unproven {
				if failN++; failN >= peerFailThreshold {
					b.session.Store(nil) // not answering: drop back to the handshake path and re-init there
					b.ci.Store(nil)
					b.st.down("peer-dead", "udp")
					failN = 0
				}
			} else {
				failN = 0
			}
			if b.cryptoOn && b.sealer() == nil {
				// A FAILOVER rotation just cleared the crypto session — loop back NOW to send the
				// re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so recovery is ~1 RTT rather than ~1s (matters for live streams). Clear mode has
				// no session/handshake so this never fires there; a duplicated init is harmless.
				continue
			}
		}
		var wait time.Duration
		if (b.sealer() == nil && b.cryptoOn) || unproven {
			wait = handshakeRetransmitWait() // retransmit the handshake, or re-probe an unproven endpoint, faster than keepalive
		} else {
			wait = keepaliveInterval(b.keepalive, b.psk)
		}
		select {
		case <-b.closeCh:
			return
		case <-b.wake: // the session was cleared under us: re-decide the interval instead of sleeping it out
		case <-time.After(wait):
		}
	}
}

func (b *UDP) sendInit() {
	peer := b.peer.Load()
	if peer == nil {
		return
	}
	// Reuse the current ephemeral across retransmits — regenerate ONLY to start a fresh handshake cycle
	// (ci==nil). Regenerating on every 1s retransmit races the reply: on a link whose init->resp RTT
	// exceeds the retransmit interval, the response is checked against a newer ephemeral and always dropped.
	ci := b.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		b.ci.Store(ci)
	}
	b.writeCtrl(crypto.InitMsg(b.psk, ci), peer)
}

func (b *UDP) send(typ byte, payload []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if b.cryptoOn && b.sealer() == nil {
		return // no session yet
	}
	frame, err := b.frame(typ, payload)
	if err != nil {
		return
	}
	b.writeCtrl(frame, to)
}

func iff(cond bool, a, b []byte) []byte {
	if cond {
		return a
	}
	return b
}

var errBadFrame = errors.New("core: bad frame")
