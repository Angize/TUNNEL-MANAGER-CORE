//go:build linux

// flux transport: the same sealed core frames as the other carriers, but the raw
// IPv4 carrier PROTOCOL rotates every epoch on a schedule both ends derive from
// the wall clock (see flux.go) — a signal-free moving target. Because the
// protocol moves, flux cannot bind a fixed-protocol socket the way the raw
// profiles do: it SENDS through one IP_HDRINCL socket (which lets us stamp any
// protocol number per packet) and RECEIVES through an AF_PACKET socket (which
// sees every protocol), accepting the small grace-window set of protocols the
// current/adjacent epochs derive and then authenticating with the AEAD.
//
// Session establishment (ephemeral X25519 handshake), replay guard, obfs framing
// and clear/crypto modes are identical to the raw carrier — only the socket plumbing
// and the per-epoch protocol differ. The session sealer is independent of the epoch,
// so a rotation changes how packets LOOK without touching how they OPEN: no
// re-handshake is needed when the shape rotates.
package packet

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// Flux carries L3 packets between a TUN device and a peer over a raw IPv4 carrier
// whose protocol number rotates every epoch.
type Flux struct {
	dev           *tun.Device
	keepalive     time.Duration
	deadAfterSecs int // per-tunnel self-heal deadline override (0 = default 3×keepalive/10s floor)
	rotate        time.Duration
	obfs          bool
	cryptoOn      bool
	psk           string
	cipher        string
	isClient      bool

	carrier     string // "raw" (rotate IP protocol) | "udp" (proto 17, rotate ports) | "stun" (udp + STUN header, WebRTC-shaped)
	shapeProf   string // statistical shape profile: "quic" | "video" | "webrtc" | "random"
	epochOffset int64  // manual epoch bump ("rotate now"): epoch = clock-epoch + offset (both ends set identically)

	pc     pingClock                  // times the keepalive round trip (see coreStatus.roundTrip)
	fecEnc *fecEncoder                // non-nil when FEC is on: buffers data frames into RS blocks on send
	fecDec *fecDecoder                // non-nil when FEC is on: reassembles + reconstructs blocks on receive
	rxSrc  atomic.Pointer[net.IPAddr] // src of the packet currently feeding fecDec (deliver reads it)

	sendFd int // AF_INET SOCK_RAW + IP_HDRINCL: builds each packet's IPv4 header (any protocol)
	pktFd  int // AF_PACKET SOCK_DGRAM: receives every IPv4 frame regardless of protocol

	localIP atomic.Pointer[net.IPAddr] // our source IP toward the peer
	peer    atomic.Pointer[net.IPAddr] // current known peer (server learns it)
	// replySrc (server) is the local IP the client dialed = the source to answer FROM, so a destination-
	// pool client rotating across our IPs gets each reply from the SAME IP it dialed (flux crafts every
	// header via buildIP4, so srcIP() feeds the source directly). Set per received frame in netToTun
	// (AF_PACKET exposes the dst at pkt[16:20]) BEFORE handleCrypto, so even the handshake RESP answers
	// from the dialed IP. Tracks destination rotation. Committed pre-AEAD (post source-filter): the
	// synchronous replies are always correct; only the async download source could be briefly steered by
	// a source-spoofing attacker (availability-only, self-correcting) — see the raw carrier's note.
	replySrc atomic.Pointer[net.IP]
	srcAllow map[string]struct{} // admitted peer IPs (4-byte keys): the client's source pool on a server, the destination pool on a client; set once before Run, then read-only
	session  atomic.Pointer[sealerBox]
	curShape atomic.Pointer[fluxShape] // this epoch's shape (refreshed each second by rotateWatcher)
	rp       replayGuard
	staged   []*stagedBox // server: bounded set of sessions staged by recent inits, each promoted only once a frame opens under it
	hsCache  initCache    // server: recent inits -> responses (compute-DoS replay cache; receive-goroutine-only)
	ci       atomic.Pointer[crypto.Ephemeral]
	lastRx   atomic.Int64 // unix-nano of the last authenticated frame (client staleness)
	hbRx     atomic.Int64 // unix-nano of the last REAL inbound frame — feeds the status heartbeat; 0 until the peer answers (v2.48.7)
	// peerAnswered gates the clear-mode heal: set when the CURRENT endpoint replies, cleared on
	// rotation, so a just-jumped-to (unproven) endpoint's burn is never falsely cleared. Mirrors UDP.
	peerAnswered atomic.Bool
	logEp        atomic.Int64 // last epoch whose rotation was logged (rotation visibility)

	// leak owns the raw-PREROUTING DROP rules that stop OUR kernel ICMP-rejecting this carrier's
	// exotic protocol / unbound UDP port. AF_PACKET taps every frame before that chain, so flux
	// still receives everything. See antileak_linux.go; the rule set is fluxDropMatches.
	leak      antiLeaker
	sendMu    sync.RWMutex // senders RLock around the raw-fd Sendto; Close takes the write lock before closing it
	sendDown  bool         // set under sendMu.Lock in Close: no more Sendto on the (about-to-be-closed) raw fd
	srcWarned sync.Map     // source string -> struct{}: sources already reported as unusable, one line each (see adoptableSource)
	sendErr   sendErrLog   // throttled data-plane send-failure logging (see sendlog.go)
	desync    desyncCfg    // client-only fake-packet desync (decoys emitted before each handshake); zero value = off
	inj       *l2inject    // AF_PACKET injector for bad-checksum decoys (IP_HDRINCL repairs the checksum); nil unless a badsum/both mode is on
	dsSend    desyncSend   // outcome of the decoy TRANSMITS — opening inj/sendFd says nothing about them
	closeCh   chan struct{}
	closeOnce sync.Once

	st      *coreStatus         // client-only: precise self-heal event ring written to the status file (nil = off)
	pp      *PeerPool           // client-only: destination-IP rotation pool (nil = single fixed peer, no rotation)
	poolIPs map[string]struct{} // client-only: the destination pool's IPs (4-byte keys) — see provenFrom
	sp      *PeerPool           // client-only: source-IP rotation pool (nil = single fixed source; swaps the crafted header src)
}

// SetDeadAfter (client) tightens the session-stale deadline to the per-tunnel dead_after_secs so the
// tunnel re-handshakes faster than the default (3×keepalive). No-op for secs<=0. Call before Run.
func (f *Flux) SetDeadAfter(secs int) bool {
	if secs <= 0 {
		return false
	}
	f.deadAfterSecs = secs
	// The SERVER of a connectionless carrier holds no dead window at all — there is no connection to
	// reap and clientLoop, the only reader of this value, never starts. Report that rather than let
	// main print "self-heal deadline set to Ns" over a number nothing will ever consult.
	return f.isClient
}

// SetStatusPath (client, optional) wires a status-file event ring so self-heal re-handshakes and
// recoveries surface in the panel's system log. Call before Run(). No-op path leaves it off.
func (f *Flux) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := f.peer.Load(); p != nil {
		peer = p.String()
	}
	f.st = newCoreStatus(path, "flux:"+f.carrier+" · "+peer, roleOf(f.isClient))
}

// SetDesync (client, optional) turns on fake-packet desync: `count` decoy packets go out
// just before each fresh handshake to mis-sync a stateful DPI. flux always has its
// IP_HDRINCL send socket (sendFd), so no extra socket is needed. Call before Run(). No-op
// on the server.
func (f *Flux) SetDesync(on bool, ttl, count int, mode string) {
	if !f.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if d.usesBadsum() { // bad-checksum decoys must bypass IP_HDRINCL (which repairs the checksum)
		// The injector carries no peer — sendFakes passes the CURRENT destination per decoy — so it
		// needs nothing from the tunnel state here and follows a destination rotation on its own.
		if inj, err := newL2Inject(); err != nil {
			// "both" still has its TTL decoys; "badsum" has none, so there desync becomes a no-op.
			if d.mode == "both" {
				log.Printf("flux: bad-checksum decoys disabled (AF_PACKET: %v) — the TTL decoys still fire", err)
			} else {
				log.Printf("flux: bad-checksum decoys disabled (AF_PACKET: %v) — fake-desync is now a no-op (mode=badsum has no TTL decoys)", err)
			}
		} else {
			f.inj = inj
		}
	}
	f.desync = d
}

// sendFakes emits the configured decoy packets to the peer just before a real handshake,
// each shaped like this epoch's carrier (raw proto / udp+ports / stun) with a per-decoy
// TTL/checksum and random payload, so a DPI sees them as the same flow. Reuses the
// IP_HDRINCL send socket and the same sendMu/sendDown guard as carrierOut. flux never
// forges addresses, so src/dst are the real ones.
func (f *Flux) sendFakes(to *net.IPAddr) {
	if !f.desync.on || to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	if sh == nil {
		return
	}
	src := f.srcIP()
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	for _, sp := range f.desync.specs() {
		body := fakePayload()
		proto, seg := f.carrierSeg(body, sh, src, to.IP)
		out := buildIP4Ext(src, to.IP, proto, sp.ttl, sp.badSum, seg)
		if out == nil {
			continue
		}
		if sp.badSum {
			// Bad-checksum decoy: inject at L2 so the forged checksum survives (IP_HDRINCL
			// would repair it). Best-effort; the injector guards its own fd against Close.
			// Pass the SAME destination the decoy's IPv4 header carries, so a rotated destination
			// is framed for ITS next hop rather than the one resolved at startup.
			if f.inj != nil {
				f.dsSend.note("flux", f.inj.sendTo(to.IP, out))
			}
			continue
		}
		f.sendMu.RLock()
		if !f.sendDown {
			f.dsSend.note("flux", syscall.Sendto(f.sendFd, out, 0, &sa))
		}
		f.sendMu.RUnlock()
	}
}

func newFlux(dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int, isClient bool) *Flux {
	if carrier == "" {
		carrier = "udp"
	}
	if shape == "" {
		shape = "random"
	}
	f := &Flux{
		dev: dev, keepalive: ka, rotate: rotate, obfs: obfs, cryptoOn: cryptoOn,
		psk: psk, cipher: cipher, carrier: carrier, shapeProf: shape, epochOffset: epochOffset,
		isClient: isClient, sendFd: -1, pktFd: -1, closeCh: make(chan struct{}),
	}
	f.leak.init(f.closeCh, func(peer net.IP) func() { return addFluxDrop(peer, carrier) })
	sh := deriveFluxShape(psk, f.epochNow(), shape)
	f.curShape.Store(&sh)
	// Seed logEp to the startup epoch so rotateWatcher logs the FIRST genuine rotation — even one that
	// lands before its first tick — instead of the prev==0 guard swallowing it as the startup seed; the
	// startup epoch itself stays unlogged because the first same-epoch tick then sees prev==sh.epoch.
	f.logEp.Store(sh.epoch)
	// emit sends each ready FEC packet (data/parity shard) to the current peer wrapped
	// in the carrier; deliver feeds each recovered frame back into the normal crypto
	// path with the source of the packet that completed the block.
	f.fecEnc, f.fecDec = newFecPair(fec, fecData, fecParity, "flux",
		func(pkt []byte) {
			if p := f.peer.Load(); p != nil {
				f.carrierOut(pkt, p)
			}
		},
		func(frame []byte) {
			if s := f.rxSrc.Load(); s != nil {
				f.handleCrypto(frame, s)
			}
		})
	return f
}

// epochNow is the current shape epoch: the clock-derived epoch plus any manual
// offset. Both ends carry the same offset (set from config on a "rotate now"), so
// bumping it advances the moving target fleet-wide with no wire signal.
func (f *Flux) epochNow() int64 { return fluxEpochAt(f.rotate, time.Now()) + f.epochOffset }

// openFluxSockets opens the shared IP_HDRINCL sender and AF_PACKET receiver. The
// sender is created for bip's protocol number, but IP_HDRINCL means the protocol
// we stamp in each packet's header is what actually goes on the wire, so one
// socket serves every epoch's protocol.
func openFluxSockets() (send, pkt int, err error) {
	send, err = openHdrincl(protoBIP)
	if err != nil {
		return -1, -1, err
	}
	pkt, err = openAfpacket()
	if err != nil {
		syscall.Close(send)
		return -1, -1, err
	}
	return send, pkt, nil
}

// DialFlux (client role) targets peerIP. peerIP may be a plain IPv4 or "ip:port"
// (the port is ignored — the raw carrier has no ports of its own).
func DialFlux(peerIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, errBadFrame
	}
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, true)
	f.sendFd, f.pktFd = send, pkt
	f.peer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		f.localIP.Store(&net.IPAddr{IP: lip})
	}
	f.leak.scope(ip) // the peer is known up front — suppress kernel ICMP for its frames now
	return f, nil
}

// ListenFlux (server role) waits to learn the peer from the first authenticated
// frame. listenIP is accepted for signature parity with the other carriers but is
// not used: AF_PACKET receives on every interface and the source filter is the peer.
func ListenFlux(listenIP string, dev *tun.Device, ka, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, ka, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, false)
	f.sendFd, f.pktFd = send, pkt
	return f, nil
}

// Run blocks until a loop fails (a socket or the device closes).
func (f *Flux) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- f.tunToNet() }()
	go func() { errc <- f.netToTun() }()
	go f.rotateWatcher()
	// BOTH ends publish. The server's own lastRx proves the CLIENT->SERVER direction — a fact only that
	// end can see — and without it a server had no liveness signal at all and fell back to probing.
	dw := int64(f.deadWin().Seconds())
	f.st.setDW(dw)                             // publish it so the reader ages hb against it...
	go heartbeat(f.st, &f.hbRx, f.closeCh, dw) // ...and pace the republish off it, so an idle tunnel reads live, not half-open
	if f.isClient {
		go f.clientLoop()
	}
	return <-errc
}

// Close tears down the sockets, the client loop, and any kernel anti-ICMP rule installed for
// the peer. Closing the fd does NOT wake a thread blocked in the AF_PACKET recvfrom, so the
// receive loop exits on its next SO_RCVTIMEO tick (<=1s) via its closeCh check, not instantly.
func (f *Flux) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	if f.fecEnc != nil {
		f.fecEnc.Close() // stop the FEC flush timer before the raw fd is closed (else a late Sendto hits a reused fd)
	}
	f.leak.teardown() // closeCh is already closed above, so any in-flight re-scope bails out first
	// Block new sends and wait for any in-flight Sendto to finish BEFORE closing the raw fd,
	// so a sibling goroutine (clientLoop / rotateWatcher / FEC emit) can't Sendto on a closed
	// fd number that has since been reused by another socket.
	f.sendMu.Lock()
	f.sendDown = true
	f.sendMu.Unlock()
	if f.sendFd >= 0 {
		syscall.Close(f.sendFd)
	}
	if f.pktFd >= 0 {
		syscall.Close(f.pktFd)
	}
	if f.inj != nil { // AF_PACKET bad-checksum injector (its own fd guard makes this Close-safe)
		f.inj.close()
	}
	return nil
}

func (f *Flux) sealer() Sealer {
	if box := f.session.Load(); box != nil {
		return box.s
	}
	return nil
}

func (f *Flux) srcIP() net.IP {
	if rs := f.replySrc.Load(); rs != nil { // server: craft the reply FROM the IP the client dialed
		return *rs
	}
	if l := f.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

// fluxPadMax picks the padding budget for a frame. Control frames (keepalives) are
// the fingerprintable fixed-size packets, so their budget follows the shape profile
// (curShape.ctrlPad) to blend into the mimicked traffic's small-packet histogram.
// Data frames keep the standard budget so the node's MTU reservation still holds.
func (f *Flux) fluxPadMax(typ byte) int {
	if typ == typeData {
		return obfsDataPadMax
	}
	if sh := f.curShape.Load(); sh != nil {
		return sh.ctrlPad
	}
	return obfsCtrlPadMax
}

// body builds the framed (magic/type/sealed or obfs) bytes — identical to the UDP
// and raw carriers — before the IPv4 header is prepended.
func (f *Flux) body(typ byte, payload []byte) ([]byte, error) {
	return sealBody(f.sealer(), f.obfs, typ, payload, f.fluxPadMax(typ))
}

// carrierSeg maps the configured carrier to the (IP proto, L4 payload) that frames body under shape
// sh: raw tunnels body directly under the epoch's rotating IP protocol; udp/stun wrap it in a UDP
// segment (stun prepends a STUN Binding header so the flow reads as WebRTC signalling). Shared by the
// real send path (carrierOut) and the decoy path (sendFakes) so the two can never drift on how a
// carrier frames a packet — a DPI must see the decoys shaped exactly like the real traffic.
func (f *Flux) carrierSeg(body []byte, sh *fluxShape, src, dst net.IP) (proto int, payload []byte) {
	switch f.carrier {
	case "raw":
		return sh.proto, body
	case "stun":
		return protoUDP, buildUDPSeg(src, dst, sh.sport, sh.dportSTUN, buildSTUN(body))
	default: // udp
		return protoUDP, buildUDPSeg(src, dst, sh.sport, sh.dport, body)
	}
}

// carrierOut builds the full IPv4 packet in this epoch's shape around body and sends
// it to the peer via the IP_HDRINCL socket. The header source is our real IP and
// the destination is the real peer — flux rotates the carrier, it does not forge
// addresses. The "raw" carrier stamps the epoch's rotating IP protocol; the "udp"
// carrier stamps protocol 17 and wraps the frame in a UDP header whose ports rotate.
// When FEC is on, body already carries the 1-byte FEC type tag (data/parity/pass).
func (f *Flux) carrierOut(body []byte, to *net.IPAddr) {
	if to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	src := f.srcIP()
	proto, seg := f.carrierSeg(body, sh, src, to.IP)
	out := buildIP4(src, to.IP, proto, seg)
	if out == nil {
		return // buildIP4 refused an oversize packet (16-bit IPv4 length); not reachable under normal MTUs
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	// Guard the bare-fd Sendto: an RLock lets Close() (write lock) wait for in-flight sends
	// and then flip sendDown before syscall.Close, so we never Sendto on a closed/reused fd.
	// The RLock is uncontended in steady state and cheap next to the syscall itself.
	f.sendMu.RLock()
	if !f.sendDown {
		// carrierOut is the SINGLE egress for data, handshake and keepalive frames, so a persistent
		// failure here is indistinguishable from "the peer is filtering us": the tunnel goes stale,
		// re-handshakes, burns pool endpoints and rotates, all on a healthy network with no output.
		if err := syscall.Sendto(f.sendFd, out, 0, &sa); err != nil {
			f.sendErr.note("flux", err)
		}
	}
	f.sendMu.RUnlock()
}

// stunMagic is the STUN magic cookie (RFC 5389) at bytes 4..8 of every STUN message.
const stunMagic = 0x2112A442

// stunAttrType is the STUN attribute we stash the tunnel payload in. 0x8022 is
// SOFTWARE (RFC 5389): a comprehension-OPTIONAL attribute (top bit set) that a STUN
// parser is required to skip when it can't use it — so a DPI that walks the attribute
// stream sees a well-formed, ignorable attribute rather than opaque trailing bytes.
const stunAttrType = 0x8022

// buildSTUN wraps payload in a STUN Binding request so the carrier parses as WebRTC.
// The payload is carried as ONE STUN attribute — [type:2][len:2][value][pad to a
// 4-byte boundary] — and the STUN message-length counts the padded attribute, so it
// is a multiple of 4 exactly as a real STUN attribute stream is. Without this a
// parser that walks attributes (they must be 4-byte aligned) could tell our opaque
// ciphertext apart from genuine STUN. Fields: type 0x0001 (Binding Request, high two
// bits zero as STUN requires), the magic cookie, and a random 96-bit transaction id
// (indistinguishable from a real one — it is meant to look random).
func buildSTUN(payload []byte) []byte {
	valLen := len(payload)
	padded := (valLen + 3) &^ 3 // round the attribute value up to a 4-byte boundary
	msgLen := 4 + padded        // 4-byte attribute header + padded value
	h := make([]byte, 20+msgLen)
	binary.BigEndian.PutUint16(h[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(h[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(h[4:8], stunMagic)
	_, _ = rand.Read(h[8:20]) // transaction id
	binary.BigEndian.PutUint16(h[20:22], stunAttrType)
	binary.BigEndian.PutUint16(h[22:24], uint16(valLen)) // attribute length excludes the pad
	copy(h[24:], payload)
	// h[24+valLen : 24+padded] stays zero — the attribute's alignment padding.
	return h
}

// parseSTUN strips the 20-byte STUN header AND the 4-byte attribute header, returning
// exactly the attribute value (ignoring the 4-byte-boundary pad). It requires the
// magic cookie so a stray non-STUN datagram on the port is rejected before the AEAD.
func parseSTUN(pkt []byte) ([]byte, bool) {
	if len(pkt) < 24 || binary.BigEndian.Uint32(pkt[4:8]) != stunMagic {
		return nil, false
	}
	valLen := int(binary.BigEndian.Uint16(pkt[22:24])) // attribute length = real payload size (no pad)
	if 24+valLen > len(pkt) {
		return nil, false
	}
	return pkt[24 : 24+valLen], true
}

// buildUDPSeg wraps payload in a UDP header with the given ports and a correct
// checksum (over the IPv4 pseudo-header), so the udp carrier's packets are valid
// UDP datagrams any transit will forward.
func buildUDPSeg(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
	copy(h[8:], payload)
	cs := l4Checksum(src, dst, protoUDP, h)
	if cs == 0 {
		cs = 0xffff // 0 means "no checksum" in UDP; use the equivalent 0xffff
	}
	binary.BigEndian.PutUint16(h[6:8], cs)
	return h
}

// fluxDropMatches returns the iptables match fragments (one per rule) that select
// exactly this carrier's inbound traffic from peer — scoped to the carrier's own
// protocol/ports so it never drops another tunnel's packets to the same peer:
//   - raw:  one rule per experimental protocol in the pool (-p <proto>)
//   - stun: one rule per STUN destination port (-p udp --dport <p>)
//   - udp:  one rule per QUIC/STUN/WebRTC destination port (-p udp --dport <p>)
func fluxDropMatches(peer net.IP, carrier string) [][]string {
	s := peer.String()
	var out [][]string
	switch carrier {
	case "raw":
		for _, p := range fluxProtoPool {
			out = append(out, []string{"-s", s, "-p", strconv.Itoa(p)})
		}
	case "stun":
		for _, dp := range fluxStunDports {
			out = append(out, []string{"-s", s, "-p", "udp", "--dport", strconv.Itoa(int(dp))})
		}
	default: // udp
		for _, dp := range fluxDportPool {
			out = append(out, []string{"-s", s, "-p", "udp", "--dport", strconv.Itoa(int(dp))})
		}
	}
	return out
}

// addFluxDrop installs best-effort raw-PREROUTING DROP rules for exactly this
// carrier's traffic from peer, so the kernel never ICMP-rejects our frames while a
// co-located tunnel (e.g. raw/bip on proto 253) to the same peer keeps working.
// AF_PACKET taps before this chain, so flux's receive is unaffected. Returns a
// cleanup func that removes every rule it managed to install (nil if none).
func addFluxDrop(peer net.IP, carrier string) func() {
	var added [][]string
	for _, m := range fluxDropMatches(peer, carrier) {
		args := append([]string{"-t", "raw", "-A", "PREROUTING"}, append(append([]string{}, m...), "-j", "DROP")...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			log.Printf("flux: anti-leak rule not installed (kernel may ICMP-reject our carrier): %v: %s", err, strings.TrimSpace(string(out)))
			continue
		}
		added = append(added, m)
	}
	if len(added) == 0 {
		return nil
	}
	return func() {
		for _, m := range added {
			del := append([]string{"-t", "raw", "-D", "PREROUTING"}, append(append([]string{}, m...), "-j", "DROP")...)
			_ = exec.Command("iptables", del...).Run()
		}
	}
}

// netToTun receives every IPv4 frame via AF_PACKET, keeps those that match the
// current carrier's grace window (raw: IP protocol ∈ prev/current/next epoch; udp:
// protocol 17 with a destination port ∈ the epochs' ports) and — once the peer is
// known — whose source is the peer, strips the carrier header, then authenticates
// and dispatches. SOCK_DGRAM strips the link header, so each frame starts at the IPv4 header.
func (f *Flux) netToTun() error {
	// grace* persist ACROSS frames (the closure captures them by reference, exactly like the old loop
	// vars): the live per-epoch carrier protocol/port sets, refreshed only when the epoch ticks over.
	var graceEpoch int64 = -1
	var graceP map[int]bool
	var graceD map[uint16]bool
	return afpacketLoop(f.pktFd, f.closeCh, func(pkt []byte, ihl int) {
		if e := f.epochNow(); e != graceEpoch {
			graceP = graceProtos(f.psk, e, f.shapeProf)
			graceD = graceDports(f.psk, e, f.shapeProf, f.carrier)
			graceEpoch = e
		}
		var body []byte
		if f.carrier == "raw" {
			if !graceP[int(pkt[9])] {
				return // not a flux carrier protocol for any live epoch
			}
			body = pkt[ihl:]
		} else { // udp or stun carrier — both ride protocol 17
			if int(pkt[9]) != protoUDP || len(pkt) < ihl+8 {
				return
			}
			if !graceD[binary.BigEndian.Uint16(pkt[ihl+2:ihl+4])] {
				return // not a flux carrier destination port for any live epoch
			}
			body = pkt[ihl+8:] // strip the UDP header
			if f.carrier == "stun" {
				inner, ok := parseSTUN(body)
				if !ok {
					return // not a STUN datagram
				}
				body = inner
			}
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		if peer := f.peer.Load(); peer != nil && !src.IP.Equal(peer.IP) && !f.srcAllowed(src.IP) {
			// only the peer's frames are ours (AF_PACKET sees all hosts); a pooled server ALSO admits the
			// client's other known source IPs so a source rotation reaches crypto and learnPeer re-binds.
			return
		}
		if !f.isClient { // server: answer THIS frame (and its handshake RESP) from the IP the client dialed (pkt[16:20]=dst)
			// Unlike raw (which learns the dst from kernel-verified IP_PKTINFO), flux trusts pkt[16:20] — but
			// this store is already gated by the PSK-derived grace proto/port match above AND the peer/source
			// filter, so a party without the PSK can't reach it to steer the egress source; and it is only the
			// ASYNC download source (availability-only, self-correcting) per the field's note.
			d := append(net.IP(nil), pkt[16:20]...)
			f.replySrc.Store(&d)
		}
		if f.fecDec != nil {
			// netToTun is the sole reader, so rxSrc is stable for the whole input()
			// call (the decoder delivers recovered frames synchronously within it).
			f.rxSrc.Store(src)
			f.fecDec.input(body)
		} else {
			f.handleCrypto(body, src)
		}
	})
}

// tunToNet reads L3 packets from TUN, seals them, and sends to the peer.
func (f *Flux) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := f.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := f.peer.Load()
		if peer == nil {
			continue // server has not learned the client yet
		}
		if f.cryptoOn && f.sealer() == nil {
			continue // handshake not finished yet; drop (L4 retransmits)
		}
		body, err := f.body(typeData, buf[:n])
		if err != nil {
			log.Printf("flux: seal error: %v", err)
			continue
		}
		if f.fecEnc != nil {
			f.fecEnc.addData(body) // buffered into an RS block; shards go out via the emit callback
		} else {
			f.carrierOut(body, peer)
		}
	}
}

func (f *Flux) handleCrypto(body []byte, addr *net.IPAddr) {
	if !f.cryptoOn {
		if len(body) < 2 || body[0] != magic {
			return
		}
		f.markRx()            // the peer is answering (clear mode has no session to prove it)
		f.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
		f.learnPeer(addr)
		f.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
		return
	}
	if s := f.sealer(); s != nil {
		if typ, session, seq, payload, oerr := f.openWith(s, body); oerr == nil && f.rp.ok(session, seq) {
			f.markRx()            // the session is answering
			f.provenFrom(addr.IP) // ...and, unless it came from an endpoint we left, the current one is alive
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	// A frame that did not open under the live session may open under a session STAGED by a recent
	// init; promote a candidate only when a frame actually opens under it, so a replayed init cannot
	// tear down the live session or its replay window. The live session was tried first above, so an
	// established tunnel never reaches this loop; on the normal path the set holds one candidate.
	for _, st := range f.staged {
		if typ, session, seq, payload, oerr := f.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			f.session.Store(st.box)
			f.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
			f.rp = st.rp
			f.staged = nil
			f.markRx() // a pending session promoted -> genuine inbound
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	f.tryHandshake(body, addr)
}

// learnPeer records the peer address (and, on the server, the local source IP
// toward it) once a frame authenticates, and installs the peer's anti-ICMP rule the
// first time (the server has no peer to scope it to until now).
func (f *Flux) learnPeer(addr *net.IPAddr) {
	// The destination pool owns the client's peer: don't rebind it from a reply's source (a pool
	// server can answer from a different IP than the client dialed). Servers (pp==nil) still learn the
	// client here, which is what lets them follow a client's SOURCE rotation.
	if f.pp == nil {
		f.peer.Store(addr)
	}
	f.learnLocalIP(addr.IP)
	// ASYNC: this runs on the AF_PACKET receive goroutine. A rotation/pin has normally already
	// re-scoped to this peer, so the common case is the atomic-load fast path and nothing happens;
	// the hand-off covers what a rotation cannot know up front — a server following the client's
	// SOURCE rotation, and the brief window where a pool server still answers from its old IP.
	//
	// The CURRENT peer, not the frame's sender — see the raw twin for the full reasoning. Short
	// version: the rule set is single-scoped, a pooled client deliberately keeps accepting frames from
	// the endpoint a rotation just left, and passing the sender let each of those drag the rules off
	// the destination the tunnel is actually using.
	if p := f.peer.Load(); p != nil {
		f.leak.scopeAsync(p.IP)
	}
}

// learnLocalIP records, once, the local source IP the kernel routes toward peer — the tcp profile's
// checksum needs it. Idempotent: a no-op after the first success, so repeated inbound frames and a
// staged pending session don't re-resolve it.
func (f *Flux) learnLocalIP(peer net.IP) {
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(peer); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
}

// openWith tries to open one datagram under a specific session sealer, touching no
// session/replay state so a frame can be tried against both the live and a pending session.
func (f *Flux) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, body, f.obfs)
}

func (f *Flux) tryHandshake(body []byte, addr *net.IPAddr) {
	if f.isClient {
		ci := f.ci.Load()
		if ci == nil {
			return
		}
		eResp, err := crypto.ParseResp(f.psk, ci.Pub, body)
		if err != nil {
			return
		}
		s, err := crypto.SessionSealer(f.cipher, f.psk, ci, eResp, ci.Pub, eResp, true)
		if err != nil {
			return
		}
		f.rp = replayGuard{}
		f.session.Store(&sealerBox{s: s})
		f.fecDec.reset() // a fresh session: the peer may have restarted its block numbering
		// Clear the ephemeral so a replayed resp captured on-path hits the ci==nil guard above
		// instead of re-parsing and wiping the fresh anti-replay window. A legitimate
		// re-handshake regenerates a fresh ci in sendInit (ci==nil path).
		f.ci.Store(nil)
		f.markRx()               // server RESP arrived: genuine inbound (green on a real connect)
		f.provenFrom(addr.IP)    // ...and it answered the endpoint we are addressing
		f.st.reconnected("flux") // recovery after a self-heal (nil-safe; silent on first connect)
		return
	}
	// Compute-DoS mitigation: an attacker replaying captured valid inits at high rate
	// would otherwise force a fresh ECDH+HKDF (GenerateEphemeral+SessionSealer) per packet.
	// If this init matches one we recently answered (while a pending session is current),
	// re-send the already-computed response and return before that expensive crypto. The
	// handshake outcome is unchanged (staged/promote-on-open is untouched); a genuinely new
	// init falls through to the full handshake below. The cache is a small LRU (not a
	// single entry) so alternating two captured inits cannot bust it. It is touched only on
	// this single receive goroutine (like staged), so no locking is needed.
	if len(f.staged) > 0 {
		if resp, ok := f.hsCache.get(body); ok {
			f.sendCtrl(resp, addr)
			return
		}
	}
	eInit, err := crypto.ParseInit(f.psk, body)
	if err != nil {
		return
	}
	sr, err := crypto.GenerateEphemeral()
	if err != nil {
		return
	}
	s, err := crypto.SessionSealer(f.cipher, f.psk, sr, eInit, eInit, sr.Pub, false)
	if err != nil {
		return
	}
	// Stage the new session as PENDING; the live session and its replay window survive until
	// a frame actually opens under these new keys (see handleCrypto), so a replayed init
	// cannot wedge the tunnel. Peer rebinding is likewise deferred to that first frame.
	f.staged = stageSession(f.staged, s)
	f.learnLocalIP(addr.IP)
	if msg2 := crypto.RespMsg(f.psk, eInit, sr); msg2 != nil {
		// Cache this init and its response so a replay of the same init (while a staged session
		// is still current) is served without recomputing the crypto above. put copies body
		// (it aliases the receive buffer); msg2 is a fresh slice, safe to keep.
		f.hsCache.put(body, msg2)
		f.sendCtrl(msg2, addr)
	}
}

func (f *Flux) dispatch(typ byte, payload []byte, addr *net.IPAddr) {
	switch typ {
	case typePing:
		f.send(typePong, nil, addr)
	case typePong:
		// The answer to our own ping: the ONE locally observable fact that covers both
		// directions at once — it got there, and the reply got back.
		f.st.roundTrip(f.pc.rtt())
	case typeData:
		if _, err := f.dev.Write(payload); err != nil {
			log.Printf("flux: tun write error: %v", err)
		}
	}
}

// deadWin is the session-stale window this carrier enforces: sessionStaleWindow over the
// keepalive and the per-tunnel dead_after_secs. Published as `dw` in the status file so the
// panel judges the dot by the same number the carrier acts on.
func (f *Flux) deadWin() time.Duration { return sessionStaleWindow(f.keepalive, f.deadAfterSecs) }

// sessionStale mirrors Raw.sessionStale: if the client has heard nothing
// authenticated for ~3×keepalive (min 10s) the server probably restarted, so the
// client drops the dead session and re-handshakes rather than pinging forever
// under a key the fresh server cannot open.
func (f *Flux) sessionStale() bool { return staleSince(f.lastRx.Load(), f.deadWin()) }

// markRx stamps a genuine inbound frame: both the failover clock (lastRx) and the liveness heartbeat
// (hbRx). hbRx is set ONLY here (proven inbound), so hb stays 0 until the peer answers — a connecting
// tunnel reads yellow, not a false green. Failover-clock seeds (connect / rotation) must NOT call this.
func (f *Flux) markRx() {
	now := time.Now().UnixNano()
	f.lastRx.Store(now)
	f.hbRx.Store(now)
}

// provenFrom marks the CURRENT destination as answering. A timed rotation keeps the session, so for
// about one RTT after a jump the endpoint we LEFT is still answering; those frames are ours and are
// delivered, but they say nothing about the endpoint we just moved to — counting them as proof is what
// let a blocked IP hide behind the one it replaced. A frame from any address that is NOT another pool
// endpoint is unattributable (a server that replies from one fixed IP rather than the dialed one) and
// still counts, so an unusual listen config degrades to the old behaviour instead of a rotation storm.
func (f *Flux) provenFrom(ip net.IP) {
	if ip != nil && len(f.poolIPs) > 0 {
		if p := f.peer.Load(); p != nil && !p.IP.Equal(ip) {
			if v4 := ip.To4(); v4 != nil {
				if _, other := f.poolIPs[string(v4)]; other {
					return
				}
			}
		}
	}
	f.peerAnswered.Store(true)
}

// SetPeerPool (client) wires a destination-IP rotation pool: a peer whose handshake never completes
// is burned and the client re-points at the next live endpoint (a proactive timer also rotates).
// nil / single-endpoint = no rotation. main wires it via the shared SetPeerPool type assertion.
func (f *Flux) SetPeerPool(pp *PeerPool) {
	if f.isClient {
		f.pp = pp
		if pp != nil {
			// ONE map, two readers, so the two views of the pool can never drift apart:
			//  - poolIPs: see provenFrom — tells "the endpoint we left" apart from "an unattributable source".
			//  - srcAllow: admit every pool endpoint as a reply source. A timed rotation keeps the session
			//    (see rotatePeerFlux), so for about one RTT after the jump the server is still answering
			//    from the endpoint we just left. Those frames are ours and open under the same keys; the
			//    strict single-source filter would drop them and turn a seamless rotation back into a loss
			//    burst. All pool addresses belong to the same server node and the AEAD still authenticates
			//    every frame, so this widens nothing an attacker can use.
			m := buildSrcAllow(pp.all())
			f.poolIPs = m
			if len(m) > 0 {
				f.srcAllow = m
			}
		}
	}
}

// SetPeerSources (SERVER) records the client's known SOURCE-pool IPs so the receive filter admits a
// rotated-but-expected client source (which then authenticates via crypto and re-binds the peer),
// instead of dropping it as an unrelated host. Call before Run(); no-op on the client / empty list.
func (f *Flux) SetPeerSources(ips []string) {
	if f.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		f.srcAllow = m
	}
}

// srcAllowed reports whether ip is one of the client's known pool sources (server only). Empty set
// (non-pool tunnel, or the client) => false, so the strict single-source filter is unchanged there.
func (f *Flux) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(f.srcAllow, ip)
}

// SetSourcePool (client) wires a source-IP rotation pool: the crafted-header source IP the client
// sends FROM is cycled/burned alongside the destination. flux stamps the source per packet, so a
// rotation is just an atomic swap — no socket rebind; the server follows the new source (it learns
// the peer from received frames). nil / single-endpoint = fixed source. Call before Run().
func (f *Flux) SetSourcePool(sp *PeerPool) {
	if !f.isClient {
		return
	}
	f.sp = sp
	// Seed the initial source so the client stamps SrcIPs[0] from the first packet (matching the pool's
	// cur=0), instead of the route-derived default until the first rotation. Called before Run(), so
	// learnPeer/tryHandshake's `if localIP==nil` guard then leaves this in place.
	if sp != nil {
		if ip := adoptableSource("flux", sp, sp.current(), &f.srcWarned); ip != nil {
			f.localIP.Store(&net.IPAddr{IP: ip})
		} else {
			// Same reasoning as the raw twin: a seed the host cannot send from is stamped from the
			// FIRST packet. Burn it and let the kernel pick until rotation reaches a usable entry.
			// Unconditional: see failUnusable.
			sp.failUnusable()
		}
	}
}

// rotateSourceFlux points the client at the next source-pool IP and swaps the crafted-header source.
// No session reset is needed (the source is independent of the AEAD session); the server rebinds to
// the new source on the next authenticated frame. No-op when the pool did not move or the IP is not v4.
func (f *Flux) rotateSourceFlux(proactive bool) {
	if f.sp == nil {
		return
	}
	prev := f.sp.current() // the source we stamp today — fall back here if the next one is unusable
	addr, moved := f.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := adoptableSource("flux", f.sp, addr, &f.srcWarned)
	if ip == nil {
		// Undo the move, exactly as rotateSourceUDP does — see the raw twin for why publishing and
		// burning here would both be wrong.
		f.sp.rejectCandidate(prev)
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: rotated source to %s", addr)
	// Source swap keeps the same AEAD session (no re-handshake) -> no matching reconnect. Use event() not
	// down() so wasDown isn't armed (a phantom recovery), and carry the new source IP for the panel log.
	f.st.event("down", "src-rotate", "ip:"+addr)
}

// rotatePeerFlux points the client at the next pool endpoint (burn+advance, or a timed rotate) and
// clears the session so the next loop re-handshakes against the new destination. No-op when the pool
// did not move or the endpoint is not a valid IPv4 (flux is IPv4-only).
// A TIMED rotation keeps the AEAD session, so not one packet is dropped: every pool endpoint is an
// address of the SAME server process and the session is independent of the address. The server stamps
// its reply source from each received frame's header dst, so it follows on the first frame, and
// SetPeerPool admits the endpoint we just left for the frames still in flight from it. A FAILOVER
// rotation still clears — that endpoint stopped answering. Mirrors rotatePeerUDP / rotatePeerRaw.
func (f *Flux) rotatePeerFlux(proactive bool) {
	if f.pp == nil {
		return
	}
	addr, moved := f.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := parseIP4(hostOnly(addr))
	if ip == nil {
		return
	}
	f.peer.Store(&net.IPAddr{IP: ip})
	// Re-scope the anti-leak rule to the new destination NOW, on this goroutine (the rotation timer,
	// never the data path). The server stamps its reply source from each received frame's header dst,
	// so it answers from this IP on the first frame — which means the rule is already in place when
	// that frame lands, instead of the kernel ICMP-rejecting the first few and learnPeer then fixing
	// it from inside the receive loop.
	f.leak.scope(ip)
	if !proactive {
		f.session.Store(nil) // the endpoint failed — force a fresh handshake to the next one
		f.ci.Store(nil)
	}
	// Refresh the status descriptor to the NEW peer so "active" doesn't stay pinned to the dialed IP
	// SetStatusPath baked in — same "flux:<carrier> · <peer>" format (nil-safe when status is off).
	f.st.setActive("flux:" + f.carrier + " · " + ip.String())
	// Fresh staleness window + unproven mark for the jumped-to endpoint, so a proactive jump onto a dead
	// endpoint fails over within the dead window instead of stranding (clear mode). Mirrors rotatePeerUDP.
	f.lastRx.Store(time.Now().UnixNano())
	f.peerAnswered.Store(false)
	log.Printf("flux: rotated destination to %s", addr)
	if proactive {
		// Seamless: nothing was cleared, so there is no re-handshake and nothing for a "reconnect" to
		// pair with. event() records the jump WITHOUT arming wasDown, like the source rotation above.
		f.st.event("down", "peer-rotate", "ip:"+addr)
		return
	}
	f.st.down("peer-rotate", "ip:"+addr) // clears the session -> re-handshake -> reconnect pairs the down
}

// adoptPeerFlux re-points the client at the pool's CURRENT destination — used when an operator pin has
// just jumped the pool to a chosen endpoint — and clears the session so the next loop re-handshakes there.
func (f *Flux) adoptPeerFlux() {
	if f.pp == nil {
		return
	}
	ip := parseIP4(hostOnly(f.pp.current()))
	if ip == nil {
		return
	}
	f.peer.Store(&net.IPAddr{IP: ip})
	f.leak.scope(ip) // pre-scope on the pin poller, exactly as rotatePeerFlux does
	f.session.Store(nil)
	f.ci.Store(nil)
	// Refresh the status descriptor to the pinned peer so "active" tracks the current destination
	// (same "flux:<carrier> · <peer>" format as SetStatusPath; nil-safe when status is off).
	f.st.setActive("flux:" + f.carrier + " · " + ip.String())
	// The same two resets rotatePeerFlux performs, and for the same reason: a pin jumps to an endpoint
	// that has proven NOTHING yet. Leaving peerAnswered true from the PREVIOUS endpoint lets the very
	// next loop tick treat the newly pinned one as proven — clearing its burn, emitting a false heal,
	// and releasing the pin through pinLanded() before it had actually landed, which resumes normal
	// rotation and defeats the operator pick. lastRx likewise stayed recent from the old endpoint, so
	// the dead window for the new one was measured from a frame it never sent.
	f.lastRx.Store(time.Now().UnixNano())
	f.peerAnswered.Store(false)
	log.Printf("flux: pinned destination to %s", ip)
	// "Make this active" is a deliberate operator jump — SILENT, like udp/tcp and the ws edge pool: only
	// the active endpoint changes, no down/up in the event ring. The session clear above still forces the
	// re-handshake onto the pinned peer and setActive (above) keeps "active" tracking it. Emitting
	// down("peer-pin") here armed a paired reconnect and surfaced a manual jump as a rotation event.
}

// adoptSourceFlux swaps the crafted-header source to the pool's CURRENT source (an operator source pin).
// Like rotateSourceFlux it leaves the AEAD session intact — the source is stamped per packet.
func (f *Flux) adoptSourceFlux() {
	if f.sp == nil {
		return
	}
	addr := f.sp.current()
	ip := adoptableSource("flux", f.sp, addr, &f.srcWarned)
	if ip == nil {
		f.sp.failUnusable() // the jump is already ended; pull the IP out of rotation too (see failUnusable)
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: pinned source to %s", ip)
	f.sp.pinLandedOn(addr) // the swap IS the landing — see adoptSourceUDP
	// Silent for the same reason as the destination pin: the source is stamped per packet so the AEAD
	// session survives — nothing to reconnect, nothing to log. The source pool's status file shows it.
}

// ProbeAllNow retests every suspect/dead endpoint on both pools at once (the panel "probe now" control,
// delivered as SIGHUP). No-op unless pooled.
func (f *Flux) ProbeAllNow() {
	probeAllPools(f.pp, f.sp)
}

// pinPollLoop polls the pools' cmd files on a 1s ticker and applies any operator pin (re-pointing the
// live dataplane at the pinned endpoint via pollPins). Runs until Close.
func (f *Flux) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, f.closeCh, f.adoptPeerFlux, f.adoptSourceFlux, f.rotatePeerFlux, f.rotateSourceFlux)
}

func (f *Flux) clientLoop() {
	failN := 0        // consecutive handshake retransmits (or unanswered probes) -> the endpoint may be dead
	unproven := false // the current destination has not answered since we jumped to it -> probe at 1s, not keepalive
	rc := newRotationController(f.pp, f.sp)
	if rc.active() {
		go f.pinPollLoop(rc)
	}
	// Seed the staleness baseline NOW (clear mode). Without it, sessionStale() returns false while
	// lastRx==0, so a clear-mode failover-only pool whose first endpoint is dead never fires. Mirrors UDP.
	f.lastRx.Store(time.Now().UnixNano())
	for {
		if f.cryptoOn && f.sealer() != nil && f.sessionStale() {
			f.session.Store(nil)
			f.ci.Store(nil)
			log.Print("flux: no reply from the peer's session — re-handshaking (peer likely restarted)")
			f.st.down("stale", "flux") // precise reason for the panel log (nil-safe when off)
		}
		// Clear mode has no handshake whose failure would drive failover, so a dead pool endpoint would
		// otherwise strand the tunnel forever. Use receive-staleness (the peer pongs our pings). Mirrors UDP.
		if !f.cryptoOn && rc.active() && f.sessionStale() {
			rc.fail(f.rotatePeerFlux, f.rotateSourceFlux)
			f.lastRx.Store(time.Now().UnixNano()) // fresh window even if the pool couldn't move (single endpoint / source-only)
			f.peerAnswered.Store(false)           // stale -> the current endpoint is no longer proven answering
			f.st.down("stale", "flux")
		}
		if f.cryptoOn && f.sealer() == nil {
			unproven = false // the handshake path already ticks at 1s and drives its own failover
			f.sendInit()
			if failN++; rc.active() && failN >= peerFailThreshold {
				rc.fail(f.rotatePeerFlux, f.rotateSourceFlux) // burn+advance dest; walk source once dests cycle
				failN = 0
			}
		} else {
			// Heal transient burns on endpoints proving themselves. Clear mode has no handshake, so use
			// the data plane (peerAnswered), so a just-jumped-to endpoint's burn is never falsely cleared.
			// Heal only what the CURRENT endpoint has EARNED. "failN > 0" alone used to be proof: it could
			// only be non-zero in crypto mode after handshake retransmits, and reaching this branch at all
			// meant the handshake had just succeeded. Now that a timed rotation keeps the session, failN
			// also counts unanswered probes on an endpoint we have merely jumped to — so the old signal
			// cleared the burn of an endpoint that had proven nothing, and a blocked IP was un-burned on
			// every visit and never dropped out of rotation. peerAnswered is the proof, in both modes.
			if f.peerAnswered.Load() && (failN > 0 || (!f.cryptoOn && rc.active())) {
				healEvents(f.st, rc) // this endpoint is answering — clear transient burns, release a landed pin, emit any heal
			}
			rc.proactive(f.rotatePeerFlux, f.rotateSourceFlux, time.Now())
			// Ping AFTER the rotation, not before: on a rotating tick this frame is the first thing the
			// NEW destination sees, and it is what makes the server stamp its replies from that IP.
			f.pc.mark()
			f.st.keepaliveSent()
			f.send(typePing, nil, f.peer.Load())
			// The endpoint a timed rotation just jumped to has proven NOTHING, and because the session
			// survives, no handshake failure will ever say so. Count unanswered ticks here — AFTER the
			// jump, so the very next wait is already the 1s probe interval — on the same threshold the
			// handshake path uses. Checking before the rotation cost a full keepalive first, which let
			// sessionStale (a whole dead window) win the race and turned a blocked IP into a ~30s hole.
			if unproven = f.cryptoOn && rc.active() && !f.peerAnswered.Load(); unproven {
				if failN++; failN >= peerFailThreshold {
					f.session.Store(nil) // not answering: drop back to the handshake path, which burns and advances
					f.ci.Store(nil)
					f.st.down("peer-dead", "flux")
					rc.fail(f.rotatePeerFlux, f.rotateSourceFlux)
					failN = 0
				}
			} else {
				failN = 0
			}
			if f.cryptoOn && f.sealer() == nil {
				// A FAILOVER rotation just cleared the crypto session — loop back NOW to send
				// the re-handshake init immediately, instead of first sleeping the 1s retransmit interval
				// below, so the rotation gap is ~1 RTT rather than ~1s (matters for live streams). Clear
				// mode has no session/handshake so this never fires there; a duplicated init is harmless
				// (the server dedups via the init cache).
				continue
			}
		}
		wait := keepaliveInterval(f.keepalive, f.psk)
		if (f.cryptoOn && f.sealer() == nil) || unproven {
			wait = handshakeRetransmitWait() // retransmit the handshake, or re-probe an unproven endpoint, faster than keepalive
		}
		select {
		case <-f.closeCh:
			return
		case <-time.After(wait):
		}
	}
}

func (f *Flux) sendInit() {
	peer := f.peer.Load()
	if peer == nil {
		return
	}
	// Reuse the current ephemeral across retransmits — regenerate only for a fresh handshake
	// cycle (ci==nil). Regenerating each 1s retransmit races the reply on high-RTT links: the
	// resp (verified against the current ci) would always check against a newer ephemeral and
	// be dropped, so the handshake could never complete on exactly the throttled links we target.
	ci := f.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		f.ci.Store(ci)
		// Fresh handshake cycle (not a 1s retransmit): desync the DPI right before the init.
		f.sendFakes(peer)
	}
	f.sendCtrl(crypto.InitMsg(f.psk, ci), peer)
}

// sendCtrl sends a control/handshake frame. Under FEC it is tagged passthrough so
// the peer's decoder forwards it straight through instead of parsing it as a shard
// (or holding it in a block). `to` may differ from the learned peer — e.g. a
// server's handshake reply to the init's source before the peer is committed.
func (f *Flux) sendCtrl(body []byte, to *net.IPAddr) {
	f.carrierOut(fecTag(f.fecEnc, body), to)
}

func (f *Flux) send(typ byte, payload []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if f.cryptoOn && f.sealer() == nil {
		return
	}
	body, err := f.body(typ, payload)
	if err != nil {
		return
	}
	f.sendCtrl(body, to)
}

// rotateWatcher refreshes the cached send-side shape every second (so carrierOut
// never pays for an HKDF per packet) and logs each rotation, so an operator — and
// the netns PoC — can see the moving target change with no wire signal. It only
// observes the clock; the derivation both ends run is what keeps them in lock-step.
func (f *Flux) rotateWatcher() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-f.closeCh:
			return
		case <-t.C:
			sh := deriveFluxShape(f.psk, f.epochNow(), f.shapeProf)
			f.curShape.Store(&sh)
			if prev := f.logEp.Swap(sh.epoch); prev != sh.epoch && prev != 0 {
				switch f.carrier {
				case "raw":
					log.Printf("flux: rotated to epoch %d (raw carrier proto %d)", sh.epoch, sh.proto)
				case "stun":
					log.Printf("flux: rotated to epoch %d (stun carrier :%d)", sh.epoch, sh.dportSTUN)
				default:
					log.Printf("flux: rotated to epoch %d (udp carrier :%d)", sh.epoch, sh.dport)
				}
			}
		}
	}
}
