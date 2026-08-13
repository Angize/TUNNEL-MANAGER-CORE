//go:build linux

// This file implements the "raw" transport: the same core frames as the UDP carrier (udp.go), but each
// frame is wrapped in a raw-IP profile header (rawEncap) and shipped over a raw IPv4 socket of the
// profile's protocol number. Only the socket and the profile wrap differ. A raw socket needs CAP_NET_RAW
// and receives EVERY packet of that protocol, so frames are source-filtered and then AEAD-authenticated.
package packet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Raw carries L3 packets between a TUN device and a peer over a raw IPv4 socket.
type Raw struct {
	conn      *net.IPConn
	dev       *tun.Device
	keepalive time.Duration
	obfs      bool
	cryptoOn  bool
	psk       string
	cipher    string
	profile   string
	isClient  bool
	icmpID    uint16 // ICMP echo identifier; PSK-derived and shared by both ends on the icmp profile so replies match requests through a stateful ICMP filter (random elsewhere, ignored on receive)
	spi       uint32 // per-session ESP Security Parameters Index (esp profile; constant like a real SA)
	port      uint16 // tcp/udp profiles: the SERVER port stamped on the forged header (0 = the default 443)

	proto int
	// link is the addressing + admission layer: a directLink for the ordinary raw carrier,
	// a forgedLink for any IP-spoofing configuration. It owns the send/receive mechanism, the
	// reply address, and the source-filter decision; everything above it is shared (see
	// iplink_linux.go). Set once in DialRaw/ListenRaw before Run, then read-only.
	link ipLink

	localIP atomic.Pointer[net.IPAddr] // our source IP toward the peer (for TCP/UDP checksums)
	peer    atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	// replySrc (server, non-decoy) is the local IP the client dialed, i.e. the source to answer FROM, so a
	// destination-pool client that rotates across our IPs gets each reply from the SAME IP it dialed. Set
	// per received frame in recvConnLoop BEFORE the frame is handled, so even the handshake RESP answers
	// from the dialed IP. Committed pre-AEAD, so only the ASYNC download source could be briefly steered.
	replySrc  atomic.Pointer[net.IP]
	noPktinfo sync.Once           // one-shot warning: server frames arrived without IP_PKTINFO, so replySrc stays unset
	srcWarned sync.Map            // source string -> struct{}: sources already reported as unusable, one line each (see adoptableSource)
	sendErr   sendErrLog          // throttled data-plane send-failure logging (see sendlog.go)
	srcAllow  map[string]struct{} // admitted peer IPs (4-byte keys): the client's source pool on a server, the destination pool on a client; set once before Run, then read-only
	session   atomic.Pointer[sealerBox]
	rp        replayGuard
	staged    []*stagedBox // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache   initCache    // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci        atomic.Pointer[crypto.Ephemeral]
	seq       atomic.Uint32
	// Synthetic-TCP-profile state (tcp profile only; ignored by the others): a per-session
	// ISN and a constant peer-ISN we "acknowledge", so the forged segments carry an advancing
	// sequence and a non-zero ACK — a live-established-flow look — instead of the tell-tale
	// seq+1 / ack=0 that a stateful DPI flags as forged.
	tcpISN   uint32
	tcpAck   uint32
	tcpBytes atomic.Uint32 // cumulative tcp-profile payload bytes; drives the realistic seq advance
	// RFC 7323 timestamps, the option a real timestamped flow stamps on EVERY data segment. tsBase is
	// this session's random offset (a real TSval is a host clock plus an unguessable per-connection
	// offset, never a small number), tsStart anchors the millisecond clock, and tsEcr is the peer's last
	// TSval to echo back — what makes the two directions read as one conversation.
	tsBase  uint32
	tsStart time.Time
	tsEcr   atomic.Uint32
	lastRx  atomic.Int64 // unix-nano of the last authenticated frame (client staleness)
	// peerAnswered gates the clear-mode heal: set when the CURRENT endpoint replies, cleared on
	// rotation, so a just-jumped-to (unproven) endpoint's burn is never falsely cleared. Mirrors UDP.
	peerAnswered atomic.Bool

	fecEnc  *fecEncoder                // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec  *fecDecoder                // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxAddr  atomic.Pointer[net.IPAddr] // src of the packet currently feeding fecDec (deliver reads it)
	rxSport atomic.Uint32              // ...and its carrier source port, same lifetime, same single reader

	// cliPort is the CLIENT's carrier source port for this conversation, 0 = the fixed rawClientPort.
	// One field, two readings: on the client it is the port we stamp as source and re-roll while the
	// tunnel runs; on the server it is the port we stamp as DESTINATION, learned from an authenticated
	// frame. The server needs it because a reply aimed at a port the client never sent from reaches a
	// stateful middlebox as an unsolicited flow and is dropped -- the client's own receive path does not
	// care, since rawDecap skips the carrier header by length and never reads a port.
	cliPort     atomic.Uint32
	sportRandom bool // client: re-roll cliPort for the life of the tunnel. Server: widen the anti-leak rule.

	// leak owns the filter-OUTPUT DROP rules that stop the receiving kernel answering this
	// profile's carrier packets (icmp echo reply / udp port-unreachable / tcp RST). Wired only for
	// an unforged link, by DialRaw/ListenRaw; see rawDropMatches and antileak_linux.go.
	leak     antiLeaker
	sendMu   sync.RWMutex // senders RLock around a bare-fd Sendto (the link's spoofFd or the desync fakeFd); Close write-locks before closing either
	sendDown bool         // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) fds

	// Fake-packet desync (client only). desync holds the decoy parameters; fakeFd is a dedicated
	// IP_HDRINCL socket for low-TTL decoys, opened only when desync is on AND spoofing did not already
	// open one to borrow (-1 when unused). inj is an AF_PACKET injector for bad-checksum decoys, which
	// must bypass IP_HDRINCL because it rewrites the checksum.
	desync desyncCfg
	fakeFd int
	inj    *l2inject
	dsSend desyncSend // outcome of the decoy TRANSMITS — opening fakeFd/inj says nothing about them
	// openFakeFd overrides the IP_HDRINCL opener (nil => openHdrincl, the real syscall). The cannot-open
	// branch in SetDesync is unreachable any other way, since the fleet and the test box both run as root.
	// Same shape as l2inject.resolve.
	openFakeFd func(int) (int, error)

	closeCh   chan struct{}
	closeOnce sync.Once
	wake      chan struct{} // client-only: cuts clientLoop's sleep short once the session is cleared elsewhere (wakeLoop)

	st      *coreStatus         // client-only: precise self-heal event ring written to the status file (nil = off)
	pp      *PeerPool           // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	poolIPs map[string]struct{} // client-only: the destination pool's IPs (4-byte keys) — see provenFrom
	sp      *PeerPool           // client-only: source-IP rotation pool (nil = fixed source; ignored under spoofSrc)
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (r *Raw) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := r.peer.Load(); p != nil {
		peer = p.String()
	}
	r.st = newCoreStatus(path, "raw:"+r.profile+" · "+peer)
}

// SetDesync (client, optional) turns on fake-packet desync: `count` decoy packets go out just before
// each fresh handshake to mis-sync a stateful DPI. It needs an IP_HDRINCL socket to stamp the decoy
// TTL/checksum, reusing the one spoofing already opened when there is one. A failure to open disables
// only the decoys, never the tunnel. Call before Run(). No-op on the server.
func (r *Raw) SetDesync(on bool, ttl, count int, mode string) {
	if !r.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if !d.on {
		return
	}
	// Only the modes that emit a LOW-TTL decoy need an IP_HDRINCL socket. mode "badsum" emits none: all
	// of its decoys go out through the AF_PACKET injector below, which is a different socket for the
	// opposite reason — IP_HDRINCL would repair the forged checksum.
	if d.usesLowTTL() && r.link.fakeFD() < 0 { // no spoof socket to borrow — open a dedicated one
		open := r.openFakeFd
		if open == nil {
			open = openHdrincl
		}
		fd, err := open(r.proto)
		if err != nil {
			// Mirror the AF_PACKET failure handling below: "both" keeps the half that still works,
			// "ttl" has no other half and really is off. sendFakes skips a low-TTL decoy on its own
			// when fd < 0, so nothing else has to know.
			if d.mode == "both" {
				log.Printf("raw: low-TTL decoys disabled (cannot open raw socket: %v) — the bad-checksum decoys still fire", err)
			} else {
				log.Printf("raw: fake-desync disabled (cannot open raw socket: %v) — mode=ttl has no bad-checksum decoys", err)
				return
			}
		} else {
			r.fakeFd = fd
		}
	}
	if d.usesBadsum() { // bad-checksum decoys must bypass IP_HDRINCL (which repairs the checksum)
		// The injector carries no peer — sendFakes passes the CURRENT destination per decoy — so it
		// needs nothing from the tunnel state here and follows a destination rotation on its own.
		if inj, err := newL2Inject(); err != nil {
			// "both" still has its TTL decoys; "badsum" has none, so there desync becomes a no-op.
			if d.mode == "both" {
				log.Printf("raw: bad-checksum decoys disabled (AF_PACKET: %v) — the TTL decoys still fire", err)
			} else {
				log.Printf("raw: bad-checksum decoys disabled (AF_PACKET: %v) — fake-desync is now a no-op (mode=badsum has no TTL decoys)", err)
			}
		} else {
			r.inj = inj
		}
	}
	r.desync = d
}

// decoySeq is the per-decoy carrier sequence for decoy index i in one batch: the live stream's
// current sequence, offset by fakeSeqGap so a decoy never collides with a real frame, plus i so the
// decoys of one batch are distinct from each other (a real ping/tcp stream increments per packet).
// Pure over (proto, seq/tcpBytes, i) so its distinctness is unit-testable without a socket.
func (r *Raw) decoySeq(i int) uint32 {
	if r.proto == protoTCP {
		return r.tcpISN + r.tcpBytes.Load() + fakeSeqGap + uint32(i)
	}
	return r.seq.Load() + fakeSeqGap + uint32(i)
}

// sendFakes emits the configured decoy packets toward the peer just before a real
// handshake. Each decoy shares the real flow's src/dst/proto (mirroring writeOut's forge
// choices, so a DPI sees them as the same flow) with a per-decoy TTL/checksum and random
// payload. Guarded by sendMu/sendDown exactly like writeOut so Close can't race the fd shut.
func (r *Raw) sendFakes(to *net.IPAddr) {
	if !r.desync.on || to == nil {
		return
	}
	fd := r.link.fakeFD()
	if fd < 0 {
		fd = r.fakeFd
	}
	src, dst := r.link.header(r.srcIP(), to)
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	for i, sp := range r.desync.specs() {
		// Wrap the decoy in the SAME profile header the real frames carry. A bare payload is well-formed only
		// on bare/ipip, whose encap is a no-op; elsewhere it puts random bytes where the carrier header belongs,
		// and a DPI cannot be desynced by something it discards as malformed. Decoys take their own sequence
		// space so they never collide with a real frame, and the per-decoy +i keeps one batch's decoys distinct.
		dseq := r.decoySeq(i)
		var dack uint32
		if r.proto == protoTCP {
			dack = r.tcpAck
		}
		body := rawEncap(r.profile, fakePayload(), src, dst, r.isClient, r.icmpID, r.port, r.cport(),
			dseq, dack, r.spi, r.tsNow(), r.tsEcr.Load(), tcpPshAck)
		out := buildIP4Ext(src, dst, r.proto, sp.ttl, sp.badSum, body)
		if out == nil {
			continue
		}
		if sp.badSum {
			// Bad-checksum decoy: inject at L2 so the forged checksum survives (IP_HDRINCL would repair it).
			// Best-effort — a cold next-hop neighbour just drops this one. Framed for `to.IP`, the address the
			// tunnel ROUTES to, which is what the real data path hands the kernel: on a spoof-dst link the
			// header dst is different, and using it would make this one packet pick a different first hop.
			if r.inj != nil {
				r.dsSend.note("raw", r.inj.sendTo(to.IP, out))
			}
			continue
		}
		if fd < 0 { // low-TTL decoy needs the IP_HDRINCL socket (opened in SetDesync)
			continue
		}
		r.sendMu.RLock()
		if !r.sendDown {
			r.dsSend.note("raw", syscall.Sendto(fd, out, 0, &sa))
		}
		r.sendMu.RUnlock()
	}
}

func newRaw(conn *net.IPConn, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, isClient bool) *Raw {
	var idb [18]byte
	_, _ = rand.Read(idb[:])
	spi := binary.BigEndian.Uint32(idb[10:14])
	if spi < 256 {
		spi += 256 // SPIs 0..255 are IANA-reserved; a real SA uses >= 256
	}
	// ICMP profile: derive the echo identifier from the PSK so BOTH ends use the SAME id. A stateful ICMP
	// filter only lets an echo REPLY through when its id matches a REQUEST it saw leave, so with
	// per-process random ids the server's replies look unsolicited and the tunnel never establishes.
	icmpID := binary.BigEndian.Uint16(idb[0:2])
	if profile == "icmp" {
		h := sha256.Sum256([]byte("tnl-core|v2|icmp-id|" + psk))
		icmpID = binary.BigEndian.Uint16(h[0:2])
	}
	return &Raw{
		conn: conn, dev: dev, keepalive: ka, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, profile: profile, isClient: isClient, fakeFd: -1,
		icmpID: icmpID, closeCh: make(chan struct{}), wake: make(chan struct{}, 1),
		tcpISN: binary.BigEndian.Uint32(idb[2:6]), tcpAck: binary.BigEndian.Uint32(idb[6:10]), spi: spi,
		tsBase: binary.BigEndian.Uint32(idb[14:18]), tsStart: time.Now(),
	}
}

// tsNow is this session's TCP timestamp: a millisecond clock plus the session's random base, which is
// what a real TSval is. Monotonic and always non-zero, because a real timestamped flow never sends 0.
func (r *Raw) tsNow() uint32 {
	v := r.tsBase + uint32(time.Since(r.tsStart)/time.Millisecond)
	if v == 0 {
		v = 1
	}
	return v
}

// dialRawBase opens the client-side raw socket for profile+rawProto and targets peerIP, returning a Raw
// with everything wired EXCEPT the ipLink (the caller sets it) and FEC. Shared by DialRaw (directLink)
// and DialSpoof (forgedLink): the datapath is identical, only the addressing layer differs. peerIP may
// carry a port, which is ignored — raw IP has none of its own.
func dialRawBase(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, rawProto, rawPort int) (*Raw, error) {
	proto, ok := rawEffProto(profile, rawProto)
	if !ok {
		return nil, fmt.Errorf("raw: unknown profile %q", profile)
	}
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, fmt.Errorf("raw: peer %q is not an IPv4 address", peerIP)
	}
	conn, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	applyConnSockBuf(conn) // this IPConn is the normal raw RX/TX socket
	r := newRaw(conn, dev, ka, obfs, cryptoOn, psk, cipher, profile, true)
	r.proto, r.port = proto, rawPortOr(rawPort)
	r.peer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		r.localIP.Store(&net.IPAddr{IP: lip})
	}
	return r, nil
}

// listenRawBase binds the server-side raw socket for profile+rawProto, returning a Raw with the
// receive socket wired EXCEPT the ipLink and FEC (the caller sets them). Shared by ListenRaw and
// ListenSpoof. listenIP may be empty, "0.0.0.0", a plain IPv4, or an "ip:port" (the port is ignored).
func listenRawBase(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, rawProto, rawPort int) (*Raw, error) {
	proto, ok := rawEffProto(profile, rawProto)
	if !ok {
		return nil, fmt.Errorf("raw: unknown profile %q", profile)
	}
	bind := net.IPv4zero
	if h := hostOnly(listenIP); h != "" && h != "0.0.0.0" {
		if ip := parseIP4(h); ip != nil {
			bind = ip
		}
	}
	conn, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: bind})
	if err != nil {
		return nil, err
	}
	// The socket buffers are NOT sized here: whether this IPConn is the data path at all is decided by the
	// link the caller installs afterwards. A spoof DECOY server reads via AF_PACKET and writes via
	// IP_HDRINCL, so sizing here would pin a multi-MiB receive buffer on a socket nothing drains.
	// server: learn which of our IPs each frame targeted, to answer from it — survivable, but never silent.
	if err := enablePktinfoDst(conn); err != nil {
		log.Printf("raw: WARNING IP_PKTINFO could not be enabled (%v) — replies will leave from the kernel-default source; a destination-rotation pool will burn every IP except that one", err)
	}
	r := newRaw(conn, dev, ka, obfs, cryptoOn, psk, cipher, profile, false)
	r.proto, r.port = proto, rawPortOr(rawPort)
	return r, nil
}

// DialRaw (client role) opens a raw carrier of the profile's protocol toward peerIP. No IP spoofing —
// that is the separate "spoof" transport (DialSpoof); a raw carrier always uses an unforged directLink.
func DialRaw(peerIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, fec bool, fecData, fecParity, rawProto, rawPort int, sportRandom bool) (*Raw, error) {
	r, err := dialRawBase(peerIP, dev, ka, obfs, cryptoOn, psk, cipher, profile, rawProto, rawPort)
	if err != nil {
		return nil, err
	}
	r.link = &directLink{r: r}
	// Draw the FIRST port here, not in the loop: the loop waits out an interval before its first roll,
	// so without this the tunnel would open on the fixed default and only start moving a minute later.
	r.setSportMode(sportRandom)
	r.initFec(fec, fecData, fecParity)
	r.wireAntiLeak()
	return r, nil
}

// ListenRaw (server role) binds a raw carrier of the profile's protocol and learns the peer from the
// first authenticated frame. No IP spoofing — see ListenSpoof; a raw server always uses a directLink,
// so its IPConn IS the data path in both directions and gets the configured socket buffers.
func ListenRaw(listenIP string, dev *tun.Device, ka time.Duration, obfs, cryptoOn bool, psk, cipher, profile string, fec bool, fecData, fecParity, rawProto, rawPort int, sportRandom bool) (*Raw, error) {
	r, err := listenRawBase(listenIP, dev, ka, obfs, cryptoOn, psk, cipher, profile, rawProto, rawPort)
	if err != nil {
		return nil, err
	}
	r.link = &directLink{r: r}
	r.setSportMode(sportRandom) // server: no rolling, but the anti-leak rule must still take the range
	applyConnSockBuf(r.conn)    // a directLink server sends AND receives on this conn
	r.initFec(fec, fecData, fecParity)
	r.wireAntiLeak() // no peer yet — tryHandshake scopes it on the authenticated init, learnPeer follows it after
	return r, nil
}

// initFec wires the FEC encoder/decoder (no-op when fec is off). Data shards are
// profile-wrapped and emitted to the current peer; recovered frames re-enter the
// normal receive path with the source of the packet that completed their block.
func (r *Raw) initFec(fec bool, fecData, fecParity int) {
	r.fecEnc, r.fecDec = newFecPair(fec, fecData, fecParity, "raw",
		func(pkt []byte) {
			if p := r.peer.Load(); p != nil {
				r.writeOut(r.wire(pkt, p.IP), p)
			}
		},
		func(frame []byte) { r.deliver(frame, r.rxAddr.Load(), uint16(r.rxSport.Load())) })
}

// Run blocks until one of the loops fails (e.g. the socket or device closes).
func (r *Raw) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- r.tunToNet() }()
	go func() { errc <- r.link.recvLoop() }() // conn (netToTun) or, for a decoy server, AF_PACKET
	if r.isClient {
		go r.clientLoop()
		if r.sportRandom {
			go r.sportLoop()
		}
	}
	return <-errc
}

// Close tears down the sockets, the client loop, and any kernel anti-leak rule installed for a
// decoy destination. The AF_INET loop is woken by closing its conn; the AF_PACKET decoy loop is
// not, so it exits on the next SO_RCVTIMEO tick (<=1s) via its closeCh check.
func (r *Raw) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	if r.fecEnc != nil {
		r.fecEnc.Close() // stop the FEC flush timer before the raw fd is closed (else a late Sendto hits a reused fd)
	}
	// Block new sends and wait for any in-flight Sendto to finish before closing the link's
	// spoofFd or the desync fakeFd, so a sibling goroutine can't Sendto on a closed fd number
	// that was reused. Flip sendDown BEFORE the link closes its own fds (link.close does the
	// anti-leak + spoofFd/pktFd close under the protection of this flag).
	r.sendMu.Lock()
	r.sendDown = true
	r.sendMu.Unlock()
	r.leak.teardown()  // closeCh is already closed above, so any in-flight re-scope bails out first
	r.link.close()     // decoy-dst anti-leak rule + spoofFd + pktFd (decoy server); no-op for a directLink
	if r.fakeFd >= 0 { // dedicated desync socket (only set when the link had no fd to borrow)
		syscall.Close(r.fakeFd)
	}
	if r.inj != nil { // AF_PACKET bad-checksum injector (its own fd guard makes this Close-safe)
		r.inj.close()
	}
	return r.conn.Close()
}

func (r *Raw) sealer() Sealer {
	if box := r.session.Load(); box != nil {
		return box.s
	}
	return nil
}

func (r *Raw) srcIP() net.IP {
	if rs := r.replySrc.Load(); rs != nil { // server: answer from the IP the client dialed (also the L4-checksum src)
		return *rs
	}
	if l := r.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

// body builds the framed (magic/type/sealed or obfs) bytes for typ/payload —
// identical to the UDP carrier's frame() — before the profile wrap is applied.
func (r *Raw) body(typ byte, payload []byte) ([]byte, error) {
	return sealBody(r.sealer(), r.obfs, typ, payload, padMaxFor(typ))
}

// wire wraps a framed body in the profile carrier header, ready for the socket.
func (r *Raw) wire(body []byte, dst net.IP) []byte { return r.wireTo(body, dst, r.cport()) }

// wireTo is wire with the client's carrier port given explicitly. A handshake reply has to go back to
// the port that message arrived from, which is not necessarily where the data path is aimed.
func (r *Raw) wireTo(body []byte, dst net.IP, cport uint16) []byte {
	var seq, ack uint32
	if r.proto == protoTCP {
		// advance the sequence by this segment's payload length (a real byte stream) and
		// acknowledge a constant peer ISN — the synthetic flow receives nothing, so a real
		// ACK number would stay put. tcpBytes.Add returns the post-add total; minus n yields
		// the pre-segment offset, so concurrent sends get non-overlapping sequence ranges.
		n := uint32(len(body))
		seq = r.tcpISN + r.tcpBytes.Add(n) - n
		ack = r.tcpAck
	} else {
		seq = r.seq.Add(1)
	}
	return rawEncap(r.profile, body, r.srcIP(), dst, r.isClient, r.icmpID, r.port, cport,
		seq, ack, r.spi, r.tsNow(), r.tsEcr.Load(), tcpPshAck)
}

// writeOut sends one wrapped packet toward the real peer `to`, delegating the mechanism to the
// carrier's ipLink: a directLink writes it on the kernel-headered raw socket, a forgedLink builds
// the whole IPv4 header itself via IP_HDRINCL and Sendto()s it to the real peer (so routing reaches
// the server even when the header shows a decoy destination). See iplink_linux.go.
func (r *Raw) writeOut(pkt []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	r.link.send(pkt, to) // directLink: kernel-headered conn send; forgedLink: IP_HDRINCL Sendto
}

// pinnedSrc is the local IP this send must leave FROM, or nil to let the kernel choose — one mechanism
// (the IP_PKTINFO control message) for two callers: a SERVER answers from replySrc, the IP the client
// dialed, and a CLIENT under a source pool sends from the pool's current source. The client half also
// re-aligns the tcp/udp profiles' L4 checksum, which rawEncap computes over srcIP() and not the kernel's.
func (r *Raw) pinnedSrc() net.IP {
	if rs := r.replySrc.Load(); rs != nil { // server (non-decoy)
		return *rs
	}
	if r.sp != nil { // client under a source pool; sp is set before Run and then read-only
		if l := r.localIP.Load(); l != nil {
			return l.IP
		}
	}
	return nil
}

// replyAddr is where the server sends answers. Normally that's the packet source, but when the
// client spoofs its source the real return IP is configured (the forgedLink's fixedPeer).
func (r *Raw) replyAddr(addr *net.IPAddr) *net.IPAddr {
	return r.link.replyTo(addr)
}

// ipFlagDF is the IPv4 Don't-Fragment bit in the flags/fragment-offset field (bit 14).
const ipFlagDF = 1 << 14

// ipIDCounter backs nextIPID. It starts at a random point so two cores on one host do not emit the
// same sequence, and it is incremented per packet — the same shape Linux's own counter has, which is
// what the flow this camouflage sits in looks like.
var ipIDCounter atomic.Uint32

func init() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	ipIDCounter.Store(binary.BigEndian.Uint32(b[:]))
}

// nextIPID returns the Identification value for one crafted packet.
func nextIPID() uint16 { return uint16(ipIDCounter.Add(1)) }

// buildIP4 assembles an IPv4 header (TTL 64, valid checksum) in front of payload.
func buildIP4(src, dst net.IP, proto int, payload []byte) []byte {
	return buildIP4Ext(src, dst, proto, 64, false, payload)
}

// buildIP4Ext is buildIP4 with an explicit TTL and an option to store a deliberately WRONG header
// checksum — the two knobs a fake-packet desync needs: a low TTL expires a decoy a few hops out, and a
// bad checksum makes the receiver's IP stack drop it. ttl is clamped to 1..255.
func buildIP4Ext(src, dst net.IP, proto, ttl int, badSum bool, payload []byte) []byte {
	if len(payload) > 0xffff-20 {
		return nil // the IPv4 total-length field is 16-bit; refuse rather than truncate it (MTU-bounded, so defensive)
	}
	if ttl < 1 {
		ttl = 1
	} else if ttl > 255 {
		ttl = 255
	}
	h := make([]byte, 20+len(payload))
	h[0] = 0x45 // version 4, IHL 5 (no options)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
	// Identification and the Don't-Fragment bit. At their zero value every packet built here differs from
	// the flow it is supposed to belong to: the kernel sets DF=1 and a varying ID on the raw carrier's own
	// conn.WriteToIP sends, as it does for an ordinary socket. The ID half only ever mattered on the
	// AF_PACKET paths, since an IP_HDRINCL socket fills in a zero ID itself (raw(7)).
	binary.BigEndian.PutUint16(h[4:6], nextIPID())
	binary.BigEndian.PutUint16(h[6:8], ipFlagDF)
	h[8] = byte(ttl)
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	sum := onesComplementSum(h[:20]) // checksum field is 0 during the sum
	binary.BigEndian.PutUint16(h[10:12], sum)
	if badSum {
		// Corrupt it so an on-path DPI / the receiver's IP stack sees an invalid checksum. ^sum alone is NOT
		// always wrong: one's complement has two representations of zero, so when the correct sum is 0x0000
		// its complement 0xffff still validates. Store the complement, then verify it really fails.
		binary.BigEndian.PutUint16(h[10:12], ^sum)
		if onesComplementSum(h[:20]) == 0 {
			binary.BigEndian.PutUint16(h[10:12], ^sum^0x0001)
		}
	}
	copy(h[20:], payload)
	return h
}

// packetOutgoing is PACKET_OUTGOING: AF_PACKET delivers our own transmitted frames
// too, and those are skipped so the server never processes its own decoy replies.
const packetOutgoing = 4

// ethPIP is ETH_P_IP (the IPv4 EtherType); the AF_PACKET socket is opened for it so
// only IPv4 frames are delivered.
const ethPIP = 0x0800

// htons converts a uint16 to network byte order for the AF_PACKET protocol argument.
// Deployment targets (x86-64, arm64) are little-endian, so this is a byte swap.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// ProbeSpoof checks whether the raw sockets IP spoofing needs can be opened here.
// It opens (and immediately closes) an IP_HDRINCL raw socket and an AF_PACKET socket;
// EPERM on either means the process lacks CAP_NET_RAW. bare's protocol number (253) is
// used for the raw-socket probe. This is a local check only — see SpoofProbe.
func ProbeSpoof() SpoofProbe {
	p := SpoofProbe{}
	if fd, err := openHdrincl(253); err == nil {
		p.CapNetRaw = true
		syscall.Close(fd)
	} else {
		p.Reason = "raw sockets not permitted (needs CAP_NET_RAW / root): " + err.Error()
	}
	if fd, err := openAfpacket(); err == nil {
		p.AFPacket = true
		syscall.Close(fd)
	} else if p.Reason == "" {
		p.Reason = "AF_PACKET not permitted (needs CAP_NET_RAW / root): " + err.Error()
	}
	p.OK = p.CapNetRaw && p.AFPacket
	if p.OK {
		p.Reason = ""
	}
	return p
}

// openHdrincl opens an AF_INET raw socket of proto with IP_HDRINCL set, so the caller
// supplies the whole IPv4 header (used to forge the outer source and/or destination).
func openHdrincl(proto int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	applyFdSndBuf(fd, wantSockBuf()) // SEND buffer only — this raw sender's RX queue is never drained
	return fd, nil
}

// openAfpacket opens an AF_PACKET SOCK_DGRAM socket for IPv4 frames, used to receive
// packets addressed to the decoy destination (which the IP stack would otherwise drop).
func openAfpacket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPIP)))
	if err != nil {
		return -1, err
	}
	// A finite receive timeout makes the AF_PACKET Recvfrom loops interruptible: on Linux,
	// closing the fd does NOT wake a thread already blocked in recvfrom(2), so without this a
	// receive goroutine parks until the next matching frame and leaks past Close(). With
	// SO_RCVTIMEO the loop wakes ~once/sec with EAGAIN and re-checks closeCh.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	applyFdRcvBuf(fd, wantSockBuf()) // RECEIVE buffer only — this AF_PACKET socket is the raw-decoy/flux RX path
	return fd, nil
}

// rawSendMark tags the raw carrier's OWN outgoing packets (SO_MARK on its socket) so the icmp anti-leak
// rule can tell them from the kernel's answer. It is needed for exactly one profile: on icmp the
// server's downstream frames ARE echo replies to the peer, byte-for-byte the shape of the kernel's
// mirrored reply — and the kernel copies the request's id, so nothing inside the packet separates them.
const rawSendMark = 0x746e6c01 // "tnl\x01"

// rawDropMatches returns the filter-OUTPUT match arguments for the answers this profile provokes from
// the receiving kernel, or nil for a profile no kernel handler answers. OUTPUT and not inbound: the raw
// carrier reads a net.ListenIP socket the kernel delivers after PREROUTING and INPUT, so an inbound DROP
// takes our own receive down with it. It keys off the PROFILE, not the effective protocol number.
//
//	icmp  the SERVER's kernel mirrors every echo request back, carrying our own ciphertext. The client's
//	      kernel answers nothing, so the rule is server-only and must exempt our own replies (rawSendMark).
//	udp   BOTH kernels answer an ICMP port-unreachable quoting the packet. Ours are UDP, never ICMP.
//	tcp   BOTH kernels answer a RST, and since the carrier's flow reverses too it leaves on exactly the
//	      port pair OUR frames use at this end — so the RST flag is the whole discriminator. Ours are PSH|ACK.
func rawDropMatches(peer net.IP, profile string, port uint16, isClient, marked, sportRandom bool) [][]string {
	d := peer.String()
	switch profile {
	case "icmp":
		if isClient || !marked {
			// No mark means we cannot exempt our own downstream frames, and the rule would then
			// silently black-hole them. Leaking is bad; going dark is worse.
			return nil
		}
		return [][]string{{"-d", d, "-p", "icmp", "--icmp-type", "echo-reply",
			"-m", "mark", "!", "--mark", fmt.Sprintf("%#x", rawSendMark)}}
	case "udp":
		return [][]string{{"-d", d, "-p", "icmp", "--icmp-type", "port-unreachable"}}
	case "tcp":
		// The peer's frames arrive as rawPorts(!isClient); our kernel resets by swapping them,
		// which is rawPorts(isClient) — the same pair we send on. Only the flag tells them apart.
		psp, pdp := rawPorts(!isClient, port, 0)
		sp, dp := strconv.Itoa(int(pdp)), strconv.Itoa(int(psp))
		// A rotating client port would otherwise need the rule re-installed on every roll, and each
		// re-install is a window with NO rule in which the kernel answers. One RANGE covers every port
		// the rotation can draw, so the rule outlives them all. It is the CLIENT's side of the pair
		// that moves: our source on the client, our destination on the server.
		if sportRandom {
			rng := strconv.Itoa(rawSportLo) + ":" + strconv.Itoa(rawSportHi)
			if isClient {
				sp = rng
			} else {
				dp = rng
			}
		}
		return [][]string{{"-d", d, "-p", "tcp",
			"--sport", sp, "--dport", dp,
			"--tcp-flags", "RST", "RST"}}
	}
	// Everything else: no kernel handler answers those protocol numbers, so nothing of ours leaks.
	return nil
}

// addRawDrop installs rawDropMatches for peer, best-effort, and returns a func that removes
// exactly the rules that went in (nil if none did).
func addRawDrop(peer net.IP, profile, tun string, port uint16, isClient, marked, sportRandom bool) func() {
	type installed struct {
		match, owner []string
	}
	var added []installed
	for _, m := range rawDropMatches(peer, profile, port, isClient, marked, sportRandom) {
		args := append([]string{"-A", "OUTPUT"}, append(append([]string{}, m...), "-j", "DROP")...)
		own, ok := runRule(args, ownerMatch(tun), "raw: anti-leak")
		if !ok {
			continue
		}
		added = append(added, installed{m, own})
	}
	if len(added) == 0 {
		return nil
	}
	log.Printf("raw: anti-leak scoped to %s (%d OUTPUT rule(s), profile %s, owner %s)", peer, len(added), profile, ownerLabel(added[0].owner, tun))
	return func() {
		for _, in := range added {
			del := append([]string{"-D", "OUTPUT"}, append(append([]string{}, in.match...), "-j", "DROP")...)
			_, _ = iptablesRun(append(del, in.owner...))
		}
	}
}

// setSendMark stamps rawSendMark on everything this socket sends, so the icmp anti-leak rule can
// exempt it. Needs CAP_NET_ADMIN (raw sockets themselves only need CAP_NET_RAW), so it can fail
// on a container that has one capability and not the other — the caller must then skip the rule.
func setSendMark(conn *net.IPConn) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := sc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, rawSendMark)
	}); err != nil {
		return err
	}
	return serr
}

// wireAntiLeak wires the kernel anti-leak for a plain (unforged) raw carrier: the profiles whose
// packets the receiving kernel answers get an OUTPUT DROP scoped to the current peer, re-scoped on
// every destination rotation and pin. A spoofing link is deliberately NOT wired — its answers go to
// the forged address, not to us, and its decoy destination has its own rule (addAntiLeak).
// tunName is the tunnel this carrier belongs to, and so the owner stamped on its firewall rules.
// Empty when there is no device (a hand-built carrier in a test), which tags nothing.
// cport is the client-side carrier port to stamp right now: our own on the client, the peer's last
// authenticated one on the server. 0 means "none yet", which rawPorts reads as the fixed default.
func (r *Raw) cport() uint16 { return uint16(r.cliPort.Load()) }

// setSportMode arms the rotation. Only a profile that forges ports has one to rotate, so anything else
// stays fixed however it was configured -- and the anti-leak rule then keeps its exact match instead of
// widening to a range it has no use for. wireAntiLeak reads r.sportRandom, so this runs BEFORE it.
func (r *Raw) setSportMode(on bool) {
	r.sportRandom = on && RawProfileHasPorts(r.profile)
	if r.sportRandom && r.isClient {
		if p := rawRollSport(); p != 0 {
			r.cliPort.Store(uint32(p))
		}
	}
}

// learnClientPort records the source port of an AUTHENTICATED frame, so the server's replies go back to
// the port the client is sending from now. Server-side only: on the client the field is its own rolling
// port and adopting the peer's would overwrite it with the server's :443.
func (r *Raw) learnClientPort(sport uint16) {
	if r.isClient || sport == 0 || !RawProfileHasPorts(r.profile) {
		return
	}
	r.cliPort.Store(uint32(sport))
}

// replyPort is where a handshake answer is addressed: back at the port it arrived from, which is not
// always the learned one — tryHandshake's cached branch answers without learning. Falls back to the
// learned port for a client, for a carrier that forges none, and for a message that carried no port.
func (r *Raw) replyPort(sport uint16) uint16 {
	if r.isClient || sport == 0 || !RawProfileHasPorts(r.profile) {
		return r.cport()
	}
	return sport
}

// sportLoop re-rolls the client's carrier source port for the life of the tunnel. There is nothing to
// tear down or re-handshake: the port lives only in the forged header, no socket binds it (the carrier
// socket is opened on a PROTOCOL NUMBER), and the peer picks the new one up from the next authenticated
// frame. A roll that fails to draw simply keeps the current port.
func (r *Raw) sportLoop() {
	for {
		select {
		case <-r.closeCh:
			return
		case <-time.After(jitterFrac(rawSportEvery)):
		}
		p := rawRollSport()
		if p == 0 {
			continue
		}
		r.cliPort.Store(uint32(p))
		// ...and say so at once. Until a packet carrying the new port reaches the server, its downstream
		// is still stamped for the old one, and on a path with a stateful box those are dropped. Waiting
		// for whatever the client happens to send next makes that window a whole keepalive interval on a
		// download-only flow; one ping makes it half a round trip.
		if peer := r.peer.Load(); peer != nil {
			r.send(typePing, nil, peer)
		}
	}
}

func (r *Raw) tunName() string {
	if r.dev == nil {
		return ""
	}
	return r.dev.Name
}

func (r *Raw) wireAntiLeak() {
	marked := false
	if r.profile == "icmp" && !r.isClient {
		if err := setSendMark(r.conn); err != nil {
			log.Printf("raw: SO_MARK could not be set (%v) — the icmp anti-leak rule is OFF, so the kernel will keep mirroring our frames back to the peer", err)
		} else {
			marked = true
		}
	}
	r.leak.init(r.closeCh, func(peer net.IP) func() {
		return addRawDrop(peer, r.profile, r.tunName(), r.port, r.isClient, marked, r.sportRandom)
	})
	if p := r.peer.Load(); p != nil { // client: the peer is known at dial, so scope it now
		r.leak.scope(p.IP)
	}
}

// addAntiLeak installs a best-effort iptables rule that drops the decoy-destined
// packets in the raw table's PREROUTING chain, so the kernel does not try to forward
// or answer them. AF_PACKET taps the frame before this chain runs, so our receive path
// is unaffected. Returns a cleanup func (nil if the rule could not be installed).
func addAntiLeak(proto int, decoy net.IP, tun string) func() {
	args := []string{"-t", "raw", "-A", "PREROUTING", "-p", strconv.Itoa(proto), "-d", decoy.String(), "-j", "DROP"}
	own, ok := runRule(args, ownerMatch(tun), "raw: decoy anti-leak")
	if !ok {
		return nil
	}
	log.Printf("raw: anti-leak rule installed (iptables raw PREROUTING -p %d -d %s DROP)", proto, decoy)
	return func() {
		del := append([]string(nil), args...)
		del[2] = "-D"
		_, _ = iptablesRun(append(del, own...))
	}
}

// tunToNet reads L3 packets from TUN, seals+wraps them, and sends to the peer.
func (r *Raw) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := r.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := r.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet
		}
		if r.cryptoOn && r.sealer() == nil {
			continue // handshake not finished yet; drop (L4 retransmits)
		}
		body, err := r.body(typeData, buf[:n])
		if err != nil {
			log.Printf("raw: seal error: %v", err)
			continue
		}
		if r.fecEnc != nil {
			r.fecEnc.addData(body) // buffered into an RS block; shards go out via the emit callback
			continue
		}
		r.writeOut(r.wire(body, peer.IP), peer)
	}
}

// recvConnLoop receives raw packets on the AF_INET socket, strips the profile header, authenticates, and
// writes data frames into the TUN. It is the receive path for every configuration except a decoy server,
// which reads off the wire through the forgedLink's AF_PACKET loop instead.
func (r *Raw) recvConnLoop() error {
	buf := make([]byte, maxDatagram)
	oob := make([]byte, 128) // room for the IP_PKTINFO control message (server dst capture)
	for {
		n, oobn, _, addr, err := r.conn.ReadMsgIP(buf, oob) // ReadMsgIP == ReadFromIP for buf, plus the oob
		if err != nil {
			return err
		}
		if r.link.filterSrc() { // a forged/pinned source can't be filtered by — the AEAD authenticates
			if peer := r.peer.Load(); peer != nil && !addr.IP.Equal(peer.IP) && !r.srcAllowed(addr.IP) {
				continue // only the peer's packets are ours (raw sockets see all); a pooled server also
				// admits the client's other known source IPs so a source rotation reaches crypto and re-binds
			}
		}
		if !r.isClient { // server: answer THIS frame (and its handshake RESP) from the IP the client dialed
			var d net.IP
			if oobn > 0 {
				d = pktinfoDst(oob[:oobn])
			}
			if d != nil {
				r.replySrc.Store(&d)
			} else {
				// setsockopt reported success but the kernel delivers no (or an unparseable) cmsg —
				// replies fall back to the default source. Warn ONCE, because silently is the worst way
				// for this to break.
				r.noPktinfo.Do(func() {
					log.Printf("raw: WARNING inbound frames carry no IP_PKTINFO — replies will leave from the kernel-default source; a destination-rotation pool will burn every IP except that one")
				})
			}
		}
		r.handleRaw(buf[:n], addr)
	}
}

// afpacketLoop owns the AF_PACKET receive loop shared by the raw and flux carriers: one reusable buffer,
// the blocking Recvfrom, the close/EINTR/EAGAIN control flow, the PACKET_OUTGOING self-frame skip and the
// IPv4 header validation. It calls handle(pkt, ihl) per accepted frame, so a carrier's per-frame
// `continue` becomes a plain return. Runs until Close (nil) or a real Recvfrom error.
func afpacketLoop(fd int, closeCh <-chan struct{}, handle func(pkt []byte, ihl int)) error {
	buf := make([]byte, maxDatagram+64) // room for the IPv4 header ahead of the frame
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			select {
			case <-closeCh:
				return nil
			default:
			}
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue // EAGAIN: the SO_RCVTIMEO tick fired (lets Close be noticed); EINTR: a signal
			}
			return err
		}
		if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == packetOutgoing {
			continue // ignore frames we transmitted ourselves
		}
		pkt := buf[:n]
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue // not IPv4
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			continue
		}
		handle(pkt, ihl)
	}
}

// handleRaw strips the profile header, authenticates the frame, and dispatches it —
// the common tail of both receive paths (AF_INET and AF_PACKET). Frames that do not
// open as data are tried as handshake messages.
func (r *Raw) handleRaw(raw []byte, addr *net.IPAddr) {
	body, sport, pts, ok := rawDecap(r.profile, r.proto, raw)
	if !ok {
		return
	}
	if pts != 0 {
		// Echo the peer's TSval back as our TSecr. Unauthenticated on purpose: it is a header field a DPI
		// reads and nothing else depends on, so a forged one costs a wrong echo and nothing more.
		r.tsEcr.Store(pts)
	}
	if r.fecDec != nil {
		// The two receive loops are the only readers, so rxAddr is stable for the
		// whole input() call (the decoder delivers recovered frames synchronously).
		r.rxAddr.Store(addr)
		r.rxSport.Store(uint32(sport))
		r.fecDec.input(body)
		return
	}
	r.deliver(body, addr, sport)
}

// deliver dispatches one received frame (already de-FEC'd and de-encap'd):
// authenticated data in crypto mode, or unauthenticated legacy framing in clear mode.
func (r *Raw) deliver(body []byte, addr *net.IPAddr, sport uint16) {
	if addr == nil {
		return
	}
	if r.cryptoOn {
		r.handleCrypto(body, addr, sport)
		return
	}
	if len(body) < 2 || body[0] != magic {
		return
	}
	r.markRx()            // the peer is answering (clear mode has no session to prove it)
	r.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
	r.learnPeer(addr)
	r.learnClientPort(sport)
	r.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
}

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (r *Raw) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, body, r.obfs)
}

func (r *Raw) handleCrypto(body []byte, addr *net.IPAddr, sport uint16) {
	if s := r.sealer(); s != nil {
		if typ, session, seq, payload, oerr := r.openWith(s, body); oerr == nil && r.rp.ok(session, seq) {
			r.markRx()            // the session is answering
			r.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
			r.learnPeer(addr)
			r.learnClientPort(sport)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent
	// init; promote a candidate only when a frame actually opens under it, so a replayed init cannot
	// tear down the live session or its replay window. The live session was tried first above, so an
	// established tunnel never reaches this loop; on the normal path the set holds one candidate.
	for _, st := range r.staged {
		if typ, session, seq, payload, oerr := r.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			r.session.Store(st.box)
			r.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
			r.rp = st.rp
			r.staged = nil
			r.markRx() // a pending session promoted -> genuine inbound
			r.learnPeer(addr)
			r.learnClientPort(sport)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	r.tryHandshake(body, addr, sport)
}

// learnPeer records the peer address (and, on the server, the local source IP
// toward it, needed for the tcp profile's checksum) once a frame authenticates.
func (r *Raw) learnPeer(addr *net.IPAddr) {
	// Keep the configured/rotated peer when: a forged source/decoy means the reply address isn't the
	// real peer (the source filter is off), OR a destination pool owns the peer (r.pp) — a pool server
	// can answer from a different IP than the client dialed, and adopting it would pull the client off
	// the pool. filterSrc() is exactly !pinnedPeer, so it stands in for the old guard here.
	if r.link.filterSrc() && r.pp == nil {
		r.peer.Store(addr)
	}
	r.learnLocalIP(addr.IP)
	// ASYNC: this runs on the receive goroutine, which IS the data path, so the common case is the
	// atomic-load fast path. It scopes to the CURRENT peer, not to whoever sent this frame: the rule set is
	// single-scoped, and a pooled client keeps admitting the endpoint a rotation left, so the sender could
	// otherwise drag the rules back onto the OLD destination and re-open the leak on the live one.
	if p := r.peer.Load(); p != nil {
		r.leak.scopeAsync(p.IP)
	}
}

// learnLocalIP records, once, the local source IP the kernel routes toward peer — the tcp profile's
// checksum needs it. Idempotent: a no-op after the first success, so repeated inbound frames and a
// staged pending session don't re-resolve it.
func (r *Raw) learnLocalIP(peer net.IP) {
	if r.localIP.Load() == nil {
		if lip := routeLocalIP(peer); lip != nil {
			r.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
}

func (r *Raw) tryHandshake(body []byte, addr *net.IPAddr, hsSport uint16) {
	if r.isClient {
		ci := r.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(r.psk, ci.Pub, body)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(r.cipher, r.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		r.rp = replayGuard{}
		r.session.Store(&sealerBox{s: s})
		r.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		r.ci.Store(nil)
		r.markRx()              // server RESP arrived: genuine inbound (green on a real connect)
		r.provenFrom(addr.IP)   // ...and it answered the endpoint we are addressing
		r.st.reconnected("raw") // recovery after a self-heal (nil-safe; silent on first connect)
		return
	}
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate would otherwise force
	// a fresh ECDH+HKDF per packet, so an init matching one we recently answered (while a pending session is
	// current) is served from a small LRU before that crypto; a genuinely new init falls through.
	// Receive-goroutine-only, like staged, so no locking is needed.
	if len(r.staged) > 0 {
		if resp, ok := r.hsCache.get(body); ok {
			// Answer where it came from, but do NOT learn: a re-served response proves nothing new, so
			// a replayed init must not steer the data path. A rolling client's retransmits are
			// byte-identical, so they hit this branch forever — answered at the learned port they reach
			// one the client has left, and the tunnel never recovers.
			r.writeCtrlTo(resp, r.replyAddr(addr), r.replyPort(hsSport))
			return
		}
	}
	eInit, err := crypto.ParseInit(r.psk, body)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(r.cipher, r.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	// Stage the new session as PENDING; the live session and its replay window survive until
	// a frame actually opens under these new keys (see handleCrypto), so a replayed init
	// cannot wedge the tunnel. Peer rebinding is likewise deferred to that first frame.
	r.staged = stageSession(r.staged, s)
	r.learnLocalIP(addr.IP)
	// The RESP below is the FIRST thing this server sends, and it goes out before any data frame has
	// authenticated -- so without this it is stamped for the fixed default port while a rolling client
	// is already somewhere else in the range. On a path with a stateful box that reply is an unsolicited
	// flow and is dropped, and the handshake never completes. ParseInit above is the authentication:
	// the sender proved the PSK. The replayed-init fast path further up deliberately does NOT learn --
	// it re-serves a cached response without proving anything new, so it must not steer where we send.
	r.learnClientPort(hsSport)
	// Same authentication, same reason, for the anti-leak rule. The OUTPUT rule is per-peer, and a server
	// has no peer until a frame OPENS under a session — so for the whole handshake its kernel answers the
	// client's frames itself: an echo-reply on icmp (our own ciphertext, mirrored), an ICMP
	// port-unreachable on udp, a RST on tcp. Only while no peer is known: once one is, learnPeer owns the
	// scope, and the single rule set must not be dragged off the endpoint carrying the tunnel by an init
	// replayed from somewhere else.
	if r.peer.Load() == nil {
		r.leak.scopeAsync(addr.IP)
	}
	if msg2 := crypto.RespMsg(r.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies body
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		r.hsCache.put(body, msg2)
		r.writeCtrlTo(msg2, r.replyAddr(addr), r.replyPort(hsSport))
	}
}

// writeCtrl profile-wraps and sends a control/handshake frame, tagging it passthrough
// under FEC so the peer's decoder forwards it straight through instead of parsing it as
// a shard. to may differ from the learned peer (a server's handshake reply, or a
// forged-source client's fixed reply address).
func (r *Raw) writeCtrl(body []byte, to *net.IPAddr) { r.writeCtrlTo(body, to, r.cport()) }

// writeCtrlTo is writeCtrl addressed at an explicit client port — see wireTo.
func (r *Raw) writeCtrlTo(body []byte, to *net.IPAddr, cport uint16) {
	if to == nil {
		return
	}
	r.writeOut(r.wireTo(fecTag(r.fecEnc, body), to.IP, cport), to)
}

func (r *Raw) dispatch(typ byte, payload []byte, addr *net.IPAddr) {
	switch typ {
	case typePing:
		r.send(typePong, nil, r.replyAddr(addr))
	case typePong:
		// Nothing to record. A pong proved the endpoint answers, and provenFrom already stamped
		// that off the receive path; the rtt this used to time went to a status field nobody read.
	case typeData:
		if _, err := r.dev.Write(payload); err != nil {
			log.Printf("raw: tun write error: %v", err)
		}
	}
}

// deadWin is the session-stale window this carrier enforces.
func (r *Raw) deadWin() time.Duration { return deadWindow(r.keepalive) }

// sessionStale reports that the client has heard nothing authenticated from the server for long
// enough that the peer most likely restarted with a fresh session, so the client should drop its
// dead session and re-handshake. Without it a SERVER restart wedges the tunnel: the client keeps
// pinging under a key the fresh server can't open and never re-initiates. See UDP.sessionStale.
func (r *Raw) sessionStale() bool { return staleSince(r.lastRx.Load(), r.deadWin()) }

// markRx stamps a genuine inbound frame onto the failover clock. Failover-clock seeds
// (connect / rotation) call lastRx.Store directly, so this stays the one PROVEN-inbound stamp.
func (r *Raw) markRx() {
	r.lastRx.Store(time.Now().UnixNano())
}

// provenFrom marks the CURRENT destination as answering. A timed rotation keeps the session, so for
// about one RTT after a jump the endpoint we LEFT is still answering; those frames are ours and are
// delivered, but counting them as proof is what lets a blocked IP hide behind the one it replaced. A
// frame from an address that is not another pool endpoint is unattributable and still counts.
func (r *Raw) provenFrom(ip net.IP) {
	if ip != nil && len(r.poolIPs) > 0 {
		if p := r.peer.Load(); p != nil && !p.IP.Equal(ip) {
			if v4 := ip.To4(); v4 != nil {
				if _, other := r.poolIPs[string(v4)]; other {
					return
				}
			}
		}
	}
	r.peerAnswered.Store(true)
}

// SetPeerPool (client) wires a destination-IP rotation pool: a peer whose handshake never completes
// is burned and the client re-points at the next live endpoint (a proactive timer also rotates).
// nil / single-endpoint = no rotation. Rotates only the DESTINATION; a spoofed source (bare) is
// unaffected. main wires it via the shared SetPeerPool type assertion.
func (r *Raw) SetPeerPool(pp *PeerPool) {
	if r.isClient {
		r.pp = pp
		if pp != nil {
			// ONE map, two readers, so the two views of the pool can never drift apart. poolIPs is provenFrom's
			// "the endpoint we left" test; srcAllow admits every pool endpoint as a reply source, because a timed
			// rotation keeps the session and the server still answers from the endpoint we just left for about
			// one RTT. All pool addresses belong to one node, and the AEAD still authenticates every frame.
			m := buildSrcAllow(pp.all())
			r.poolIPs = m
			if len(m) > 0 {
				r.srcAllow = m
			}
		}
	}
}

// SetPeerSources (SERVER) records the client's known SOURCE-pool IPs so the receive filter admits a
// rotated-but-expected client source (which then authenticates via crypto and re-binds the peer),
// instead of dropping it as an unrelated host. Call before Run(); no-op on the client / empty list.
func (r *Raw) SetPeerSources(ips []string) {
	if r.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		r.srcAllow = m
	}
}

// srcAllowed reports whether ip is one of the client's known pool sources (server only). Empty set
// (non-pool tunnel, or the client) => false, so the strict single-source filter is unchanged there.
func (r *Raw) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(r.srcAllow, ip)
}

// srcAllowedIn reports whether ip is in the admit set. An empty set => false, keeping the strict
// single-source filter unchanged. Shared by raw/flux srcAllowed.
func srcAllowedIn(set map[string]struct{}, ip net.IP) bool {
	if len(set) == 0 {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	_, ok := set[string(v4)]
	return ok
}

// SetSourcePool (client) wires a source-IP rotation pool: the crafted-header source the client sends
// FROM is cycled/burned alongside the destination. raw stamps the source per packet, so a rotation is
// an atomic swap (no socket rebind); the server follows the new source. IGNORED when the source is
// forged — a forged source is a deliberate decoy that must not be rotated away. Call before Run().
func (r *Raw) SetSourcePool(sp *PeerPool) {
	if !r.isClient {
		return
	}
	if r.link.pinsSource() {
		// spoof_src owns the source field, so a rotation pool cannot also drive it. Refusing must not be
		// silent: main.go logs "source pool: N source IPs rotate=..." right after this call and has no way to
		// know it was dropped. Config validation rejects the combination; this stays as the guard.
		log.Printf("core/raw: source pool ignored — spoof_src pins the source IP (remove one of them)")
		return
	}
	r.sp = sp
	// Seed the initial source so the client stamps SrcIPs[0] from the first packet (matching the pool's
	// cur=0), instead of the route-derived default until the first rotation. Called before Run(), so
	// the later `if localIP==nil` guards (learnPeer/tryHandshake) then leave this in place.
	if sp != nil {
		if ip := adoptableSource("raw", sp, sp.current(), &r.srcWarned); ip != nil {
			r.localIP.Store(&net.IPAddr{IP: ip})
		} else {
			// Seeding an IP the host cannot send from is the worst case of all: it is stamped from the
			// FIRST packet, so the tunnel never comes up at all on the profiles whose checksum binds the
			// source. Burn it and leave the source unset — srcIP() then falls back to the kernel's pick
			// and the first rotation lands on an entry that works. Unconditional: see failUnusable.
			sp.failUnusable()
		}
	}
}

// rotateSourceRaw points the client at the next source-pool IP and swaps the crafted-header source.
// No session reset (the source is independent of the AEAD session). No-op when the pool did not move,
// the IP is not v4, or a spoofed source is in force.
func (r *Raw) rotateSourceRaw(proactive bool) {
	if r.sp == nil || r.link.pinsSource() {
		return
	}
	prev := r.sp.current() // the source we stamp today — fall back here if the next one is unusable
	addr, moved := r.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := adoptableSource("raw", r.sp, addr, &r.srcWarned)
	if ip == nil {
		// The pool advanced onto a source this host cannot send from. Undo the move, exactly as
		// rotateSourceUDP does: not one packet left prev, so publishing a src-rotate naming the new one
		// would describe a move that never happened.
		r.sp.rejectCandidate(prev)
		return
	}
	r.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("raw: rotated source to %s", addr)
	// Source swap keeps the same AEAD session (no re-handshake) -> no matching reconnect. Use event() not
	// down() so wasDown isn't armed (a phantom recovery), and carry the new source IP for the panel log.
	r.st.event("down", "src-rotate", "ip:"+addr)
}

// rotatePeerRaw points the client at the next pool endpoint. No-op when the pool did not move or the
// endpoint is not valid IPv4 (raw is IPv4-only). A TIMED rotation keeps the AEAD session — every pool
// endpoint is an address of the SAME server process, which follows on the first frame via IP_PKTINFO,
// and SetPeerPool admits the endpoint we left for what is still in flight. A FAILOVER clears it.
func (r *Raw) rotatePeerRaw(proactive bool) {
	if r.pp == nil {
		return
	}
	addr, moved := r.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	r.peer.Store(&net.IPAddr{IP: ip})
	// Pre-scope on THIS goroutine (the rotation timer), before a single frame goes to the new
	// endpoint: the one we just left stays admitted for the frames still in flight, so a rule left
	// behind on it would leak on the new one until an inbound frame reached learnPeer.
	r.leak.scope(ip)
	r.st.setActive("raw:" + r.profile + " · " + ip.String()) // refresh the frozen active descriptor to the new destination (matches SetStatusPath)
	if !proactive {
		r.session.Store(nil) // the endpoint failed — force a fresh handshake to the next one
		r.ci.Store(nil)
	}
	// Give the jumped-to endpoint a FRESH staleness window and mark it unproven, so a proactive jump
	// onto a dead endpoint fails over within the dead window instead of stranding (clear mode), and its
	// burn isn't healed until it actually replies. Mirrors rotatePeerUDP.
	r.lastRx.Store(time.Now().UnixNano())
	r.peerAnswered.Store(false)
	log.Printf("raw: rotated destination to %s", addr)
	if proactive {
		// Seamless: nothing was cleared, so there is no re-handshake and nothing for a "reconnect" to
		// pair with. event() records the jump WITHOUT arming wasDown — the same call rotateSourceRaw
		// above uses. down() here made every timed rotation read in the panel as a drop plus a self-heal.
		r.st.event("down", "peer-rotate", "ip:"+addr)
		return
	}
	r.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
	// Last, so every field the loop reads is settled before it can look. This runs on the pin poller
	// (only a failover reaches it); the timed rotation above keeps its session and returns first.
	wakeLoop(r.wake)
}

// adoptPeerRaw re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (r *Raw) adoptPeerRaw() {
	if r.pp == nil {
		return
	}
	ip := parseIP4(hostOnly(r.pp.current()))
	if ip == nil {
		return
	}
	r.peer.Store(&net.IPAddr{IP: ip})
	r.leak.scope(ip)                                         // pre-scope on the pin poller, exactly as rotatePeerRaw does
	r.st.setActive("raw:" + r.profile + " · " + ip.String()) // refresh the frozen active descriptor to the new destination (matches SetStatusPath)
	r.session.Store(nil)
	r.ci.Store(nil)
	// The same two resets rotatePeerRaw performs, and for the same reason: a pin jumps to an endpoint that
	// has proven NOTHING yet. Leaving peerAnswered true from the PREVIOUS endpoint lets the very next tick
	// treat the pinned one as proven — clearing its burn, emitting a false heal and releasing the pin
	// before it landed — and its dead window would be measured from a frame it never sent.
	r.lastRx.Store(time.Now().UnixNano())
	r.peerAnswered.Store(false)
	log.Printf("raw: pinned destination to %s", ip)
	// "Make this active" is a deliberate operator jump — SILENT, like udp/tcp and the ws edge pool: only
	// the active endpoint changes, no down/up in the event ring. The session clear above still forces the
	// re-handshake onto the pinned peer, and setActive keeps "active" tracking it.
	wakeLoop(r.wake) // the session is gone; do not make the operator's jump wait out a keepalive
}

// adoptSourceRaw swaps the crafted-header source to the pool's CURRENT source (an operator source pin).
// Ignored under a forged source (a deliberate decoy, like rotateSourceRaw); no session reset.
func (r *Raw) adoptSourceRaw() {
	if r.sp == nil || r.link.pinsSource() {
		return
	}
	addr := r.sp.current()
	ip := adoptableSource("raw", r.sp, addr, &r.srcWarned)
	if ip == nil {
		// adoptableSource has already ended the jump; pull the IP out of rotation too so the next
		// tick does not come straight back to it. Unconditional: see failUnusable.
		r.sp.failUnusable()
		return
	}
	r.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("raw: pinned source to %s", ip)
	r.sp.pinLandedOn(addr) // the swap IS the landing — see adoptSourceUDP for why no handshake follows
	// Silent for the same reason as the destination pin: the session survives a source swap, so there is
	// nothing to reconnect and nothing to log — the source pool's own status file reflects the change.
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (r *Raw) ProbeAllNow() {
	probeAllPools(r.pp, r.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin. Runs until Close.
func (r *Raw) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, r.closeCh, r.adoptPeerRaw, r.adoptSourceRaw, r.rotatePeerRaw, r.rotateSourceRaw, r.st.event)
}

func (r *Raw) clientLoop() {
	failN := 0        // consecutive handshake retransmits (or unanswered probes) -> the endpoint may be dead
	unproven := false // the current destination has not answered since we jumped to it -> probe at 1s, not keepalive
	rc := newRotationController(r.pp, r.sp)
	if rc.active() {
		go r.pinPollLoop(rc)
	}
	// Seed the staleness baseline NOW (clear mode). Without it, sessionStale() returns false while
	// lastRx==0, so a clear-mode failover-only pool whose first endpoint is dead never fires. Mirrors UDP.
	r.lastRx.Store(time.Now().UnixNano())
	for {
		if r.cryptoOn && r.sealer() != nil && r.sessionStale() {
			r.session.Store(nil) // server likely restarted — drop the dead session so we re-handshake
			r.ci.Store(nil)
			log.Print("raw: no reply from the peer's session — re-handshaking (peer likely restarted)")
			r.st.down("stale", "raw") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode has no handshake whose failure would drive failover, so a dead pool endpoint would
		// otherwise strand the tunnel forever. Use receive-staleness: the peer pongs our pings, so once it
		// stops answering (lastRx ages past the dead window) burn and advance the pool. Mirrors UDP.
		if !r.cryptoOn && r.sessionStale() {
			r.lastRx.Store(time.Now().UnixNano()) // fresh window even if the pool couldn't move (single endpoint / source-only)
			r.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			r.st.down("stale", "raw")
		}
		if r.cryptoOn && r.sealer() == nil {
			unproven = false // keep re-initing this endpoint; moving off it is the node's call, not ours
			r.sendInit()
		} else {
			// A manual jump LANDS the moment the endpoint it aimed at answers, and a landed pin has to
			// release AT ONCE: while it is live, both failover and the timed rotation are frozen behind
			// it. Keyed on the address the carrier is REALLY on, like the tcp twin, so a pin aimed
			// somewhere else is never reported as landed.
			if r.pp != nil && r.peerAnswered.Load() {
				if pa := r.peer.Load(); pa != nil {
					r.pp.pinLandedOn(pa.IP.String())
				}
			}
			// No heal here. A frame coming back proves an endpoint answered US, never that the tunnel
			// CARRIES — the node's tun probe owns that verdict and delivers it as cmdOK. All that is
			// left is bookkeeping a live carrier invalidates.
			if r.peerAnswered.Load() {
				rc.success() // live carrier: reset the attribution count and the pin-release count
			}
			rc.proactive(r.rotatePeerRaw, r.rotateSourceRaw, time.Now())
			// Ping AFTER the rotation, not before: on a rotating tick this frame is the first thing the
			// NEW destination sees, and it is what makes the server stamp its replies from that IP.
			r.send(typePing, nil, r.peer.Load())
			// The endpoint a timed rotation just jumped to has proven NOTHING, and because the session survives,
			// no handshake failure will ever say so. Count unanswered ticks here — AFTER the jump, so the very
			// next wait is already the 1s probe interval — on the same threshold the handshake path uses.
			if unproven = r.cryptoOn && rc.active() && !r.peerAnswered.Load(); unproven {
				if failN++; failN >= peerFailThreshold {
					r.session.Store(nil) // not answering: drop back to the handshake path and re-init there
					r.ci.Store(nil)
					r.st.down("peer-dead", "raw")
					failN = 0
				}
			} else {
				failN = 0
			}
			if r.cryptoOn && r.sealer() == nil {
				// A FAILOVER rotation just cleared the crypto session — loop back NOW to send the
				// re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so recovery is ~1 RTT rather than ~1s (matters for live streams). Clear mode has
				// no session/handshake so this never fires there; a duplicated init is harmless.
				continue
			}
		}
		wait := keepaliveInterval(r.keepalive, r.psk)
		if (r.cryptoOn && r.sealer() == nil) || unproven {
			wait = handshakeRetransmitWait() // retransmit the handshake, or re-probe an unproven endpoint, faster than keepalive
		}
		select {
		case <-r.closeCh:
			return
		case <-r.wake: // the session was cleared under us: re-decide the interval instead of sleeping it out
		case <-time.After(wait):
		}
	}
}

func (r *Raw) sendInit() {
	peer := r.peer.Load()
	if peer == nil {
		return
	}
	// Reuse the current ephemeral across retransmits — regenerate only for a fresh handshake
	// cycle (ci==nil). Regenerating each 1s retransmit races the reply on high-RTT links: the
	// resp (verified against the current ci) would always check against a newer ephemeral and
	// be dropped, so the handshake could never complete on exactly the throttled links we target.
	ci := r.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		r.ci.Store(ci)
		// Fresh handshake cycle (not a 1s retransmit): desync the DPI right before the init.
		r.sendFakes(peer)
	}
	r.writeCtrl(crypto.InitMsg(r.psk, ci), peer)
}

func (r *Raw) send(typ byte, payload []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if r.cryptoOn && r.sealer() == nil {
		return
	}
	body, err := r.body(typ, payload)
	if err != nil {
		return
	}
	r.writeCtrl(body, to)
}

// routeLocalIP asks the kernel which local IPv4 it would use to reach peer, by
// opening (but not sending on) a connected UDP socket. Returns nil on failure.
func routeLocalIP(peer net.IP) net.IP {
	c, err := net.Dial("udp4", net.JoinHostPort(peer.String(), "9"))
	if err != nil {
		return nil
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return la.IP.To4()
	}
	return nil
}
