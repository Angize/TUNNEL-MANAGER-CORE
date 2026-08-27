//go:build linux

package packet

import (
	"crypto/rand"
	"encoding/binary"
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

type Flux struct {
	ping     time.Duration
	dev      *tun.Device
	rotate   time.Duration
	obfs     bool
	cryptoOn bool
	psk      string
	cipher   string
	isClient bool

	carrier     string
	shapeProf   string
	epochOffset int64

	fecEnc *fecEncoder
	fecDec *fecDecoder
	rxSrc  atomic.Pointer[net.IPAddr]

	sendFd int
	pktFd  int

	localIP atomic.Pointer[net.IPAddr]
	peer    atomic.Pointer[net.IPAddr]

	replySrc atomic.Pointer[net.IP]
	srcAllow map[string]struct{}
	session  atomic.Pointer[sealerBox]
	curShape atomic.Pointer[fluxShape]
	rp       replayGuard
	staged   []*stagedBox
	hsCache  initCache
	ci       atomic.Pointer[crypto.Ephemeral]

	peerAnswered atomic.Bool
	logEp        atomic.Int64

	leak      antiLeaker
	sendMu    sync.RWMutex
	sendDown  bool
	srcWarned sync.Map
	sendErr   sendErrLog
	desync    desyncCfg
	inj       *l2inject
	dsSend    desyncSend
	closeCh   chan struct{}
	closeOnce sync.Once
	wake      chan struct{}

	st      *coreStatus
	pp      *PeerPool
	poolIPs map[string]struct{}
	sp      *PeerPool
}

func (f *Flux) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := f.peer.Load(); p != nil {
		peer = p.String()
	}
	f.st = newCoreStatus(path, "flux:"+f.carrier+" · "+peer)
}

func (f *Flux) SetDesync(on bool, ttl, count int, mode string) {
	if !f.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if d.usesBadsum() {

		if inj, err := newL2Inject(); err != nil {

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
		seg := f.carrierSeg(body, sh, src, to.IP)
		out := buildIP4Ext(src, to.IP, protoUDP, sp.ttl, sp.badSum, seg)
		if out == nil {
			continue
		}
		if sp.badSum {

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

func newFlux(dev *tun.Device, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int, isClient bool) *Flux {
	if carrier == "" {
		carrier = "udp"
	}
	if shape == "" {
		shape = "random"
	}
	f := &Flux{
		dev: dev, rotate: rotate, obfs: obfs, cryptoOn: cryptoOn, ping: pingEvery,
		psk: psk, cipher: cipher, carrier: carrier, shapeProf: shape, epochOffset: epochOffset,
		isClient: isClient, sendFd: -1, pktFd: -1, closeCh: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	f.leak.init(f.closeCh, func(peer net.IP) (func(), bool) { return addFluxDrop(peer, carrier, f.tunName()) })
	sh := deriveFluxShape(psk, f.epochNow(), shape)
	f.curShape.Store(&sh)

	f.logEp.Store(sh.epoch)

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

func (f *Flux) epochNow() int64 { return fluxEpochAt(f.rotate, time.Now()) + f.epochOffset }

func openFluxSockets() (send, pkt int, err error) {
	send, err = openHdrincl(protoBare)
	if err != nil {
		return -1, -1, err
	}

	pkt, err = openAfpacket(bpfIPProto(protoUDP), "flux: receive")
	if err != nil {
		syscall.Close(send)
		return -1, -1, err
	}
	return send, pkt, nil
}

func DialFlux(peerIP string, dev *tun.Device, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	ip := parseIP4(hostOnly(peerIP))
	if ip == nil {
		return nil, errBadFrame
	}
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, true)
	f.sendFd, f.pktFd = send, pkt
	f.peer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		f.localIP.Store(&net.IPAddr{IP: lip})
	}
	f.leak.scope(ip)
	return f, nil
}

func ListenFlux(listenIP string, dev *tun.Device, rotate time.Duration, obfs, cryptoOn bool, psk, cipher, carrier, shape string, epochOffset int64, fec bool, fecData, fecParity int) (*Flux, error) {
	send, pkt, err := openFluxSockets()
	if err != nil {
		return nil, err
	}
	f := newFlux(dev, rotate, obfs, cryptoOn, psk, cipher, carrier, shape, epochOffset, fec, fecData, fecParity, false)
	f.sendFd, f.pktFd = send, pkt
	return f, nil
}

func (f *Flux) Run() error {
	errc := make(chan error, 2)
	go func() { errc <- f.tunToNet() }()
	go func() { errc <- f.netToTun() }()
	go f.rotateWatcher()
	if f.isClient {
		f.st.trackPath(f.livePath, f.closeCh)
		go f.clientLoop()
	}
	return <-errc
}

func (f *Flux) Close() error {
	f.closeOnce.Do(func() { close(f.closeCh) })
	if f.fecEnc != nil {
		f.fecEnc.Close()
	}
	f.leak.teardown()

	f.sendMu.Lock()
	f.sendDown = true
	f.sendMu.Unlock()
	if f.sendFd >= 0 {
		syscall.Close(f.sendFd)
	}
	if f.pktFd >= 0 {
		syscall.Close(f.pktFd)
	}
	if f.inj != nil {
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
	if rs := f.replySrc.Load(); rs != nil {
		return *rs
	}
	if l := f.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

func (f *Flux) fluxPadMax(typ byte) int {
	if typ == typeData {
		return obfsDataPadMax
	}
	if sh := f.curShape.Load(); sh != nil {
		return sh.ctrlPad
	}
	return obfsCtrlPadMax
}

func (f *Flux) body(typ byte, payload []byte) ([]byte, error) {
	return sealBody(f.sealer(), f.obfs, typ, payload, f.fluxPadMax(typ))
}

func (f *Flux) carrierSeg(body []byte, sh *fluxShape, src, dst net.IP) []byte {
	if f.carrier == "stun" {
		return buildUDPSeg(src, dst, sh.sport, sh.dportSTUN, buildSTUN(body))
	}
	return buildUDPSeg(src, dst, sh.sport, sh.dport, body)
}

func (f *Flux) carrierOut(body []byte, to *net.IPAddr) {
	if to == nil || f.sendFd < 0 {
		return
	}
	sh := f.curShape.Load()
	src := f.srcIP()
	out := buildIP4(src, to.IP, protoUDP, f.carrierSeg(body, sh, src, to.IP))
	if out == nil {
		return
	}
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())

	f.sendMu.RLock()
	if !f.sendDown {

		if err := syscall.Sendto(f.sendFd, out, 0, &sa); err != nil {
			f.sendErr.note("flux", err)
		}
	}
	f.sendMu.RUnlock()
}

const stunMagic = 0x2112A442

const stunAttrType = 0x8022

func buildSTUN(payload []byte) []byte {
	valLen := len(payload)
	padded := (valLen + 3) &^ 3
	msgLen := 4 + padded
	h := make([]byte, 20+msgLen)
	binary.BigEndian.PutUint16(h[0:2], 0x0001)
	binary.BigEndian.PutUint16(h[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(h[4:8], stunMagic)
	_, _ = rand.Read(h[8:20])
	binary.BigEndian.PutUint16(h[20:22], stunAttrType)
	binary.BigEndian.PutUint16(h[22:24], uint16(valLen))
	copy(h[24:], payload)

	return h
}

func parseSTUN(pkt []byte) ([]byte, bool) {
	if len(pkt) < 24 || binary.BigEndian.Uint32(pkt[4:8]) != stunMagic {
		return nil, false
	}
	valLen := int(binary.BigEndian.Uint16(pkt[22:24]))
	if 24+valLen > len(pkt) {
		return nil, false
	}
	return pkt[24 : 24+valLen], true
}

func buildUDPSeg(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(len(h)))
	copy(h[8:], payload)
	cs := l4Checksum(src, dst, protoUDP, h)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(h[6:8], cs)
	return h
}

func fluxDropMatches(peer net.IP, carrier string) [][]string {
	s := peer.String()
	ports := fluxDportPool
	if carrier == "stun" {
		ports = fluxStunDports
	}
	out := make([][]string, 0, len(ports))
	for _, dp := range ports {
		out = append(out, []string{"-s", s, "-p", "udp", "--dport", strconv.Itoa(int(dp))})
	}
	return out
}

func (f *Flux) tunName() string {
	if f.dev == nil {
		return ""
	}
	return f.dev.Name
}

func addFluxDrop(peer net.IP, carrier, tun string) (func(), bool) {
	type installed struct {
		match, owner []string
	}
	var added []installed
	want := fluxDropMatches(peer, carrier)
	for _, m := range want {
		args := append([]string{"-t", "raw", "-I", "PREROUTING"}, append(append([]string{}, m...), "-j", "DROP")...)
		own, ok := runRule(args, ownerMatch(tun), "flux: anti-leak")
		if !ok {
			continue
		}
		added = append(added, installed{m, own})
	}
	if len(added) == 0 {
		return nil, len(want) == 0
	}
	return func() {
		for _, in := range added {
			del := append([]string{"-t", "raw", "-D", "PREROUTING"}, append(append([]string{}, in.match...), "-j", "DROP")...)
			delRule(append(del, in.owner...), "flux: anti-leak")
		}
	}, len(added) == len(want)
}

func (f *Flux) netToTun() error {

	var graceEpoch int64 = -1
	var graceD map[uint16]bool
	return afpacketLoop(f.pktFd, f.closeCh, func(pkt []byte, ihl int) {
		if e := f.epochNow(); e != graceEpoch {
			graceD = graceDports(f.psk, e, f.shapeProf, f.carrier)
			graceEpoch = e
		}
		if int(pkt[9]) != protoUDP || len(pkt) < ihl+8 {
			return
		}
		if !graceD[binary.BigEndian.Uint16(pkt[ihl+2:ihl+4])] {
			return
		}
		body := pkt[ihl+8:]
		if f.carrier == "stun" {
			inner, ok := parseSTUN(body)
			if !ok {
				return
			}
			body = inner
		}
		src := &net.IPAddr{IP: append(net.IP(nil), pkt[12:16]...)}
		if peer := f.peer.Load(); peer != nil && !src.IP.Equal(peer.IP) && !f.srcAllowed(src.IP) {

			return
		}
		if !f.isClient {

			d := append(net.IP(nil), pkt[16:20]...)
			f.replySrc.Store(&d)
		}
		if f.fecDec != nil {

			f.rxSrc.Store(src)
			f.fecDec.input(body)
		} else {
			f.handleCrypto(body, src)
		}
	})
}

func (f *Flux) tunToNet() error {
	buf := make([]byte, maxDatagram)
	for {
		n, err := f.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := f.peer.Load()
		if peer == nil {
			continue
		}
		if f.cryptoOn && f.sealer() == nil {
			continue
		}
		body, err := f.body(typeData, buf[:n])
		if err != nil {
			log.Printf("flux: seal error: %v", err)
			continue
		}
		if f.fecEnc != nil {
			f.fecEnc.addData(body)
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
		f.provenFrom(addr.IP)
		f.learnPeer(addr)
		f.dispatch(body[1], iff(body[1] == typeData, body[2:], nil), addr)
		return
	}
	if s := f.sealer(); s != nil {
		if typ, session, seq, payload, oerr := f.openWith(s, body); oerr == nil && f.rp.ok(session, seq) {
			f.provenFrom(addr.IP)
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}

	for _, st := range f.staged {
		if typ, session, seq, payload, oerr := f.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			f.session.Store(st.box)
			f.fecDec.reset()
			f.rp = st.rp
			f.staged = nil
			f.learnPeer(addr)
			f.dispatch(typ, payload, addr)
			return
		}
	}
	f.tryHandshake(body, addr)
}

func (f *Flux) learnPeer(addr *net.IPAddr) {

	if f.pp == nil {
		f.peer.Store(addr)
	}
	f.learnLocalIP(addr.IP)

	if p := f.peer.Load(); p != nil {
		f.leak.scopeAsync(p.IP)
	}
}

func (f *Flux) learnLocalIP(peer net.IP) {
	if f.localIP.Load() == nil {
		if lip := routeLocalIP(peer); lip != nil {
			f.localIP.Store(&net.IPAddr{IP: lip})
		}
	}
}

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
		f.fecDec.reset()

		f.ci.Store(nil)
		f.provenFrom(addr.IP)
		f.st.newSession()
		f.st.reconnected("flux")
		return
	}

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

	f.staged = stageSession(f.staged, s)
	f.learnLocalIP(addr.IP)

	if f.peer.Load() == nil {
		f.leak.scopeAsync(addr.IP)
	}
	if msg2 := crypto.RespMsg(f.psk, eInit, sr); msg2 != nil {

		f.hsCache.put(body, msg2)
		f.sendCtrl(msg2, addr)
	}
}

func (f *Flux) dispatch(typ byte, payload []byte, addr *net.IPAddr) {
	switch typ {
	case typePing:
		f.send(typePong, nil, addr)
	case typePong:

	case typeData:
		if _, err := f.dev.Write(payload); err != nil {
			log.Printf("flux: tun write error: %v", err)
		}
	}
}

func (f *Flux) livePath() (pathKey, bool) {
	k := pathKey{Src: f.srcIP().String()}
	if p := f.peer.Load(); p != nil {
		k.Dst = p.IP.String()
	}
	if sh := f.curShape.Load(); sh != nil {
		k.Sport, k.Dport = sh.sport, sh.dportFor(f.carrier)
	}
	return k, f.sealer() != nil
}

// The live session stays: it is what carries if the path comes back on its own, and a fresh key would
// only cost a round trip. What has to change is the ephemeral -- this rung asks for a NEW session, and
// clientLoop keeps asking until it gets one.
func (f *Flux) rehandshake() bool {
	if !f.cryptoOn || f.peer.Load() == nil {
		return false
	}
	f.ci.Store(nil)
	f.sendInit()
	f.st.down("rehandshake", "flux")
	wakeLoop(f.wake)
	return true
}

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

func (f *Flux) SetPeerPool(pp *PeerPool) {
	if f.isClient {
		f.pp = pp
		if pp != nil {
			joinStatus(f.st, pp, "dst")

			m := buildSrcAllow(pp.all())
			f.poolIPs = m
			if len(m) > 0 {
				f.srcAllow = m
			}
		}
	}
}

func (f *Flux) SetPeerSources(ips []string) {
	if f.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		f.srcAllow = m
	}
}

func (f *Flux) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(f.srcAllow, ip)
}

func (f *Flux) SetSourcePool(sp *PeerPool) {
	if !f.isClient {
		return
	}
	f.sp = sp

	if sp != nil {
		joinStatus(f.st, sp, "src")
		if ip := adoptableSource("flux", sp, sp.current(), &f.srcWarned); ip != nil {
			f.localIP.Store(&net.IPAddr{IP: ip})
		} else {

			sp.fail("unbindable")
		}
	}
}

func (f *Flux) rotateSourceFlux(proactive bool) {
	if f.sp == nil {
		return
	}
	prev := f.sp.current()
	addr, moved := f.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := adoptableSource("flux", f.sp, addr, &f.srcWarned)
	if ip == nil {

		f.sp.rejectCandidate(prev)
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: rotated source to %s", addr)

	f.st.rotated("src", "ip:"+addr, proactive)
}

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

	f.leak.scope(ip)
	if !proactive {
		f.session.Store(nil)
		f.ci.Store(nil)
	}

	f.st.setActive("flux:" + f.carrier + " · " + ip.String())

	f.peerAnswered.Store(false)
	log.Printf("flux: rotated destination to %s", addr)
	f.st.rotated("peer", "ip:"+addr, proactive)
	if proactive {
		return // a scheduled move keeps its session: there is nothing for the loop to redo
	}
	wakeLoop(f.wake)
}

func (f *Flux) pinAppliedFlux(kind, _ string) {
	if kind == "src" {
		f.adoptSourceFlux()
		return
	}
	f.adoptPeerFlux()
}

func (f *Flux) adoptPeerFlux() {
	if f.pp == nil {
		return
	}
	ip := parseIP4(hostOnly(f.pp.current()))
	if ip == nil {
		return
	}
	f.peer.Store(&net.IPAddr{IP: ip})
	f.leak.scope(ip)
	f.session.Store(nil)
	f.ci.Store(nil)

	f.st.setActive("flux:" + f.carrier + " · " + ip.String())

	f.peerAnswered.Store(false)
	log.Printf("flux: pinned destination to %s", ip)

	wakeLoop(f.wake)
}

func (f *Flux) adoptSourceFlux() {
	if f.sp == nil {
		return
	}
	addr := f.sp.current()
	ip := adoptableSource("flux", f.sp, addr, &f.srcWarned)
	if ip == nil {
		f.sp.fail("unbindable")
		return
	}
	f.localIP.Store(&net.IPAddr{IP: ip})
	log.Printf("flux: pinned source to %s", ip)
	f.sp.pinLandedOn(addr)

}

func (f *Flux) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, f.closeCh, f.pinAppliedFlux, f.rotatePeerFlux, f.rotateSourceFlux, f.st.pathEpoch)
}

func (f *Flux) clientLoop() {
	rc := newRotationController(f.pp, f.sp)
	rc.session.setDrop(f.rehandshake)
	rc.attachStatus(f.st)
	f.st.setPair(rc.pairStatus)
	if rc.polls() {
		go f.pinPollLoop(rc)
	}
	for {
		rc.proactive(f.rotatePeerFlux, f.rotateSourceFlux, time.Now())
		if handshakeOutstanding(f.cryptoOn, f.sealer(), f.ci.Load()) {
			f.sendInit()
		}
		if !f.cryptoOn || f.sealer() != nil {

			if f.pp != nil && f.peerAnswered.Load() {
				if pa := f.peer.Load(); pa != nil {
					f.pp.pinLandedOn(pa.IP.String())
				}
			}

			f.send(typePing, nil, f.peer.Load())

			if f.cryptoOn && f.sealer() == nil {

				continue
			}
		}
		wait := keepaliveInterval(f.ping, f.psk)
		if handshakeOutstanding(f.cryptoOn, f.sealer(), f.ci.Load()) {
			wait = handshakeRetransmitWait()
		}
		select {
		case <-f.closeCh:
			return
		case <-f.wake:
		case <-time.After(wait):
		}
	}
}

func (f *Flux) sendInit() {
	peer := f.peer.Load()
	if peer == nil {
		return
	}

	ci := f.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		f.ci.Store(ci)

		f.sendFakes(peer)
	}
	f.sendCtrl(crypto.InitMsg(f.psk, ci), peer)
}

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
				if f.carrier == "stun" {
					log.Printf("flux: rotated to epoch %d (stun carrier :%d)", sh.epoch, sh.dportSTUN)
				} else {
					log.Printf("flux: rotated to epoch %d (udp carrier :%d)", sh.epoch, sh.dport)
				}
			}
		}
	}
}
