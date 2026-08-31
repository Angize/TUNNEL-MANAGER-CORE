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

type Sealer interface {
	Seal(pt, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) (session uint64, seq uint64, pt []byte, err error)
}

type sealerBox struct{ s Sealer }

type stagedBox struct {
	box *sealerBox
	rp  replayGuard
}

const maxStaged = 8

func stageSession(set []*stagedBox, s Sealer) []*stagedBox {
	if len(set) >= maxStaged {
		set = set[1:]
	}
	return append(set, &stagedBox{box: &sealerBox{s: s}})
}

type UDP struct {
	ping      time.Duration
	conn      atomic.Pointer[net.UDPConn]
	rebindGen atomic.Int64
	rebindMu  sync.Mutex

	srvConns  []*net.UDPConn
	replyConn atomic.Pointer[net.UDPConn]
	rxConn    atomic.Pointer[net.UDPConn]
	rxMu      sync.Mutex

	devs     []*tun.Device
	tw       *tunWriters
	obfs     bool
	cryptoOn bool
	psk      string
	cipher   string
	isClient bool

	peer    atomic.Pointer[net.UDPAddr]
	session atomic.Pointer[sealerBox]
	rp      replayGuard
	sendErr sendErrLog
	staged  []*stagedBox
	hsCache initCache
	ci      atomic.Pointer[crypto.Ephemeral]

	peerAnswered atomic.Bool

	fecEnc *fecEncoder
	fecDec *fecDecoder
	rxAddr atomic.Pointer[net.UDPAddr]

	closeCh   chan struct{}
	closeOnce sync.Once
	wake      chan struct{}

	st      *coreStatus
	pp      *PeerPool
	poolIPs map[string]struct{}
	sp      *PeerPool
}

func (b *UDP) SetPeerPool(pp *PeerPool) {
	if b.isClient {
		b.pp = pp
		if pp != nil {
			joinStatus(b.st, pp, "dst")
			b.poolIPs = buildSrcAllow(pp.all())
		}
	}
}

var connIdle = 60 * time.Second

var pingEvery = 10 * time.Second

const handshakeRetransmit = time.Second

func handshakeRetransmitWait() time.Duration { return jitterFrac(handshakeRetransmit) }

func handshakeOutstanding(s Sealer, ci *atomic.Pointer[crypto.Ephemeral]) bool {
	return s == nil || ci.Load() != nil
}

func settleHandshake(ci *atomic.Pointer[crypto.Ephemeral]) {
	if ci.Load() != nil {
		ci.Store(nil)
	}
}

func wakeLoop(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

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
		b.session.Store(nil)
		b.ci.Store(nil)
	}

	b.peerAnswered.Store(false)
	log.Printf("core/udp: rotated destination to %s", addr)

	b.st.setActive("udp · " + ua.String())
	b.st.rotated("peer", "ip:"+addr, proactive)
	if proactive {
		return
	}
	wakeLoop(b.wake)
}

func (b *UDP) SetSourcePool(sp *PeerPool) {
	if !b.isClient {
		return
	}
	b.sp = sp

	if sp != nil {
		joinStatus(b.st, sp, "src")
		host := sp.current()
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
			if err != nil {
				log.Printf("core/udp: initial source bind to %s failed: %v", host, err)

				b.sp.fail("unbindable")
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

func (b *UDP) rotateSourceUDP(proactive bool) {
	if b.sp == nil {
		return
	}
	prev := b.sp.current()
	addr, moved := b.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: rotated source to %s", host)

		b.st.rotated("src", "ip:"+host, proactive)
		return
	}

	b.sp.rejectCandidate(prev)
}

func (b *UDP) rebindSourceTo(addr string) (string, bool) {
	host := addr
	if h, _, e := net.SplitHostPort(addr); e == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	b.rebindMu.Lock()
	defer b.rebindMu.Unlock()
	nc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		log.Printf("core/udp: source rebind to %s failed: %v", host, err)
		return "", false
	}
	applyConnSockBuf(nc)
	old := b.conn.Load()

	b.conn.Store(nc)
	b.rebindGen.Add(1)
	_ = old.Close()
	return host, true
}

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

	b.peerAnswered.Store(false)
	log.Printf("core/udp: pinned destination to %s", addr)

	b.st.setActive("udp · " + ua.String())
	wakeLoop(b.wake)
}

func (b *UDP) adoptSourceUDP() {
	if b.sp == nil {
		return
	}
	addr := b.sp.current()
	if host, ok := b.rebindSourceTo(addr); ok {
		log.Printf("core/udp: pinned source to %s", host)

		b.sp.pinLandedOn(addr)

		return
	}

	if b.sp.pinCannotLand(addr) {
		log.Printf("core/udp: manual jump to source %s abandoned — that IP will not bind on this host", addr)
	}
	b.sp.fail("unbindable")
}

func runPinPoll(rc *rotationController, closeCh <-chan struct{}, applied func(kind, key string),
	rotLow, rotHigh func(proactive bool), pathEpoch func() int64) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-t.C:
			rc.poll(rotLow, rotHigh, applied, pathEpoch)
		}
	}
}

func (b *UDP) pinAppliedUDP(kind, _ string) {
	if kind == "src" {
		b.adoptSourceUDP()
		return
	}
	b.adoptPeerUDP()
}

func (b *UDP) pinPollLoop(rc *rotationController) {
	runPinPoll(rc, b.closeCh, b.pinAppliedUDP, b.rotatePeerUDP, b.rotateSourceUDP, b.st.pathEpoch)
}

func (b *UDP) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := b.peer.Load(); p != nil {
		peer = p.String()
	}
	b.st = newCoreStatus(path, "udp · "+peer)
}

func (b *UDP) livePath() (pathKey, bool) {
	var k pathKey
	if c := b.conn.Load(); c != nil {
		k.Src, k.Sport = addrParts(c.LocalAddr())
	}
	if p := b.peer.Load(); p != nil {
		k.Dst, k.Dport = p.IP.String(), uint16(p.Port)
	}

	if b.cryptoOn {
		return k, b.sealer() != nil
	}
	return k, b.peerAnswered.Load()
}

func (b *UDP) rehandshake() bool {
	if !b.cryptoOn || b.peer.Load() == nil {
		return false
	}
	b.ci.Store(nil)
	b.sendInit()
	b.st.down("rehandshake", "udp")
	wakeLoop(b.wake)
	return true
}

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

func Dial(peerAddr string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int, extra ...*tun.Device) (*UDP, error) {
	ra, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	applyConnSockBuf(conn)
	b := &UDP{obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, isClient: true, ping: pingEvery,
		closeCh: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.initQueues(dev, extra)
	b.conn.Store(conn)
	b.peer.Store(ra)
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

func (b *UDP) initQueues(dev *tun.Device, extra []*tun.Device) {
	b.devs = append([]*tun.Device{dev}, extra...)
	b.tw = newTunWriters(b.devs)
}

func Listen(listenAddrs []string, dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, fec bool, fecData, fecParity int, extra ...*tun.Device) (*UDP, error) {
	b := &UDP{obfs: obfs, cryptoOn: cryptoOn, psk: psk, cipher: cipher, ping: pingEvery, closeCh: make(chan struct{})}
	b.initQueues(dev, extra)
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
		for _, c := range b.srvConns {
			_ = c.Close()
		}
		return nil, err
	}
	if len(b.srvConns) == 0 {
		return nil, errors.New("udp listen: no listen address")
	}
	b.replyConn.Store(b.srvConns[0])
	b.initFec(fec, fecData, fecParity)
	return b, nil
}

func (b *UDP) serverReadLoop(c *net.UDPConn) error {
	buf := make([]byte, maxDatagram)
	bat := newUDPBatch(c)
	for {
		if bat != nil {
			ds, err := bat.recv()
			if err != nil {
				return err
			}
			for _, d := range ds {
				b.rxMu.Lock()
				b.rxConn.Store(c)
				b.receive(d.pkt, d.addr)
				b.rxMu.Unlock()
			}
			continue
		}
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		b.rxMu.Lock()
		b.rxConn.Store(c)
		b.receive(buf[:n], addr)
		b.rxMu.Unlock()
	}
}

func (b *UDP) receive(pkt []byte, addr *net.UDPAddr) {
	if b.fecDec != nil {
		b.rxAddr.Store(addr)
		b.fecDec.input(pkt)
		return
	}
	b.deliver(pkt, addr)
}

func (b *UDP) learnPeer(addr *net.UDPAddr) {
	if !b.isClient {
		if c := b.rxConn.Load(); c != nil {
			b.replyConn.Store(c)
		}
	}
	b.peer.Store(addr)
}

func (b *UDP) sendConn() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	return b.replyConn.Load()
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}

func parseIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

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

	if sp != nil && sp.pinCannotLand(addr) {
		log.Printf("core/%s: manual jump to source %s abandoned — that IP is not configured on this host", tag, addr)
	}
	return nil
}

func buildSrcAllow(ips []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, s := range ips {
		if ip := parseIP4(hostOnly(s)); ip != nil {
			m[string(ip.To4())] = struct{}{}
		}
	}
	return m
}

func (b *UDP) replySock() *net.UDPConn {
	if b.isClient {
		return b.conn.Load()
	}
	if c := b.rxConn.Load(); c != nil {
		return c
	}
	return b.replyConn.Load()
}

func (b *UDP) initFec(fec bool, fecData, fecParity int) {
	b.fecEnc, b.fecDec = newFecPair(fec, fecData, fecParity, "udp",
		func(pkt []byte) {
			if p := b.peer.Load(); p != nil {
				if c := b.sendConn(); c != nil {
					if _, err := c.WriteToUDP(pkt, p); err != nil {
						b.sendErr.note("udp/fec", err)
					}
				}
			}
		},
		func(frame []byte) { b.deliver(frame, b.rxAddr.Load()) })
}

func (b *UDP) Run() error {
	errc := make(chan error, 1+len(b.devs)+len(b.srvConns))
	for _, d := range b.devs {
		d := d
		go func() { errc <- b.tunToNet(d) }()
	}
	if b.isClient {
		go func() { errc <- b.netToTun() }()
		b.st.trackPath(b.livePath, b.closeCh)
		go b.clientLoop()
	} else {
		for _, c := range b.srvConns {
			c := c
			go func() { errc <- b.serverReadLoop(c) }()
		}
	}
	return <-errc
}

func (b *UDP) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	b.tw.close()
	if b.fecEnc != nil {
		b.fecEnc.Close()
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

func (b *UDP) frame(typ byte, payload []byte) ([]byte, error) {
	return sealBody(b.sealer(), b.obfs, typ, payload, padMaxFor(typ))
}

func (b *UDP) tunToNet(dev *tun.Device) error {
	buf := make([]byte, maxDatagram)

	var tx *udpTx
	var txFor *net.UDPConn
	for {
		n, err := dev.Read(buf)
		if err != nil {
			return err
		}
		peer := b.peer.Load()
		if peer == nil {
			continue
		}
		if b.cryptoOn && b.sealer() == nil {
			continue
		}
		frame, err := b.frame(typeData, buf[:n])
		if err != nil {
			log.Printf("core: seal error: %v", err)
			continue
		}
		if b.fecEnc != nil {
			b.fecEnc.addData(frame)
			continue
		}
		c := b.sendConn()
		if c == nil {
			continue
		}
		if txFor != c {
			tx, txFor = newUDPTx(c), c
		}
		if tx != nil {
			tx.reset()
			tx.add(frame, peer)
			for !tx.full() {
				m, ok, err := dev.TryRead(buf)
				if err != nil || !ok {
					break
				}
				f, err := b.frame(typeData, buf[:m])
				if err != nil {
					continue
				}
				tx.add(f, peer)
			}
			if tx.count() > 1 {
				tx.flush(&b.sendErr)
				continue
			}
		}
		if _, err := c.WriteToUDP(frame, peer); err != nil {
			b.sendErr.note("udp", err)
		}
	}
}

func (b *UDP) netToTun() error {
	buf := make([]byte, maxDatagram)

	var bat *udpBatch
	var batFor *net.UDPConn
	for {
		gen := b.rebindGen.Load()
		c := b.conn.Load()
		if batFor != c {
			bat, batFor = newUDPBatch(c), c
		}

		if bat != nil {
			ds, err := bat.recv()
			if err != nil {
				if b.rebindGen.Load() != gen {
					continue
				}
				return err
			}
			for _, d := range ds {
				b.receive(d.pkt, d.addr)
			}
			continue
		}
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			if b.rebindGen.Load() != gen {
				continue
			}
			return err
		}
		b.receive(buf[:n], addr)
	}
}

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
	b.provenFrom(addr.IP)
	if b.pp == nil {
		b.learnPeer(addr)
	}
	pt := iff(pkt[1] == typeData, pkt[2:], nil)
	if pt != nil {
		pt = append([]byte(nil), pt...)
	}
	b.dispatch(pkt[1], pt, addr)
}

func sealBody(s Sealer, obfs bool, typ byte, payload []byte, padMax int) ([]byte, error) {
	if obfs {
		return obfsSeal(s, typ, payload, padMax)
	}
	if s != nil {
		sealed, err := s.Seal(payload, []byte{typ})
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

func (b *UDP) openWith(s Sealer, pkt []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, pkt, b.obfs)
}

func (b *UDP) handleCrypto(pkt []byte, addr *net.UDPAddr) {
	if s := b.sealer(); s != nil {
		if typ, session, seq, payload, oerr := b.openWith(s, pkt); oerr == nil && b.rp.ok(session, seq) {
			settleHandshake(&b.ci)
			b.provenFrom(addr.IP)

			if b.pp == nil {
				b.learnPeer(addr)
			}
			b.dispatch(typ, payload, addr)
			return
		}
	}

	for _, st := range b.staged {
		if typ, session, seq, payload, oerr := b.openWith(st.box.s, pkt); oerr == nil && st.rp.ok(session, seq) {
			b.session.Store(st.box)
			b.fecDec.reset()
			b.rp = st.rp
			b.staged = nil
			b.learnPeer(addr)
			b.dispatch(typ, payload, addr)
			return
		}
	}
	b.tryHandshake(pkt, addr)
}

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
		b.fecDec.reset()

		b.ci.Store(nil)
		b.provenFrom(addr.IP)
		b.st.newSession()
		b.st.reconnected("udp")
		return
	}

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

	b.staged = stageSession(b.staged, s)
	if msg2 := crypto.RespMsg(b.psk, eInit, sr); msg2 != nil {
		b.hsCache.put(pkt, msg2)
		b.writeCtrl(msg2, addr)
	}
}

func (b *UDP) writeCtrl(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	if c := b.replySock(); c != nil {
		if _, err := c.WriteToUDP(fecTag(b.fecEnc, pkt), to); err != nil {
			b.sendErr.note("udp/ctrl", err)
		}
	}
}

func (b *UDP) dispatch(typ byte, payload []byte, addr *net.UDPAddr) {
	switch typ {
	case typePing:
		b.send(typePong, nil, addr)
	case typePong:
	case typeData:
		b.tw.write(payload)
	}
}

func (b *UDP) clientLoop() {
	rc := newRotationController(b.pp, b.sp)
	rc.session.setDrop(b.rehandshake)
	rc.attachStatus(b.st)
	b.st.setPair(rc.pairStatus)
	if rc.polls() {
		go b.pinPollLoop(rc)
	}
	for {
		rc.proactive(b.rotatePeerUDP, b.rotateSourceUDP, time.Now())
		asking := b.cryptoOn && handshakeOutstanding(b.sealer(), &b.ci)
		if asking {
			b.sendInit()
		}
		if !b.cryptoOn || b.sealer() != nil {
			if b.pp != nil && b.peerAnswered.Load() {
				if pa := b.peer.Load(); pa != nil {
					b.pp.pinLandedOn(pa.String())
				}
			}

			if !b.cryptoOn && b.peerAnswered.Load() {
				b.st.newSession()
				b.st.reconnected("udp")
			}

			b.send(typePing, nil, b.peer.Load())

			if b.cryptoOn && b.sealer() == nil {
				continue
			}
		}
		wait := keepaliveInterval(b.ping, b.psk)
		if asking {
			wait = handshakeRetransmitWait()
		}
		select {
		case <-b.closeCh:
			return
		case <-b.wake:
		case <-time.After(wait):
		}
	}
}

func (b *UDP) sendInit() {
	peer := b.peer.Load()
	if peer == nil {
		return
	}

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
		return
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
