//go:build linux

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

	"golang.org/x/net/ipv4"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

type Raw struct {
	ping time.Duration
	conn *net.IPConn

	batch *ipv4.PacketConn
	dev   *tun.Device

	rxw *tunWriters

	txq      []txQueue
	obfs     bool
	psk      string
	cipher   string
	profile  string
	isClient bool
	icmpID   uint16
	spi      uint32
	port     uint16

	proto int

	link ipLink

	localIP  atomic.Pointer[net.IPAddr]
	soloPeer atomic.Pointer[net.IPAddr]

	replySrc  atomic.Pointer[net.IP]
	ours      ourIPs
	notOurDst sync.Once
	noPktinfo sync.Once
	srcWarned sync.Map
	sendErr   sendErrLog
	oobSrc    atomic.Pointer[cachedOOB]
	srcAllow  map[string]struct{}
	session   atomic.Pointer[sealerBox]
	rp        replayGuard
	staged    []*stagedBox
	hsCache   initCache
	ci        atomic.Pointer[crypto.Ephemeral]
	seq       atomic.Uint32

	tcpISN   atomic.Uint32
	tcpAck   atomic.Uint32
	peerSeen atomic.Bool
	synAcked atomic.Bool
	cliSyn   atomic.Uint32
	cliSynOK atomic.Bool
	tcpBytes atomic.Uint32

	tsBase  atomic.Uint32
	tsStart atomic.Int64
	tsEcr   atomic.Uint32

	peerAnswered atomic.Bool
	unanswered   atomic.Bool

	fecEnc  *fecEncoder
	fecDec  *fecDecoder
	rxAddr  atomic.Pointer[net.IPAddr]
	rxSport atomic.Uint32

	cliPort     atomic.Uint32
	sportRandom bool

	sportEvery int
	rotIdx     uint32
	rotPerm    rotPerm
	dports     []uint16
	txCount    atomic.Uint64
	portEpoch  atomic.Uint64

	leak     antiLeaker
	sendMu   sync.RWMutex
	sendDown bool

	desync desyncCfg
	fakeFd int
	inj    *l2inject
	dsSend desyncSend

	openFakeFd func(int) (int, error)

	closeCh   chan struct{}
	closeOnce sync.Once
	wake      chan struct{}

	st      *coreStatus
	pp      *PeerPool
	poolIPs map[string]struct{}
	sp      *PeerPool
}

func (r *Raw) SetStatusPath(path string) {
	if path == "" {
		return
	}
	peer := ""
	if p := r.dst(); p != nil {
		peer = p.String()
	}
	r.st = newCoreStatus(path, "raw:"+r.profile+" · "+peer)
	r.st.trackRot(r.rotSnapshot, r.closeCh)
}

func (r *Raw) SetDesync(on bool, ttl, count int, mode string) {
	if !r.isClient {
		return
	}
	d := newDesyncCfg(on, ttl, count, mode)
	if !d.on {
		return
	}

	if d.usesLowTTL() {
		open := r.openFakeFd
		if open == nil {
			open = openHdrincl
		}
		fd, err := open(r.proto)
		if err != nil {
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
	if d.usesBadsum() {
		if inj, err := newL2Inject(); err != nil {
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

func (r *Raw) decoySeq(i int) uint32 {
	if r.proto == protoTCP {
		return r.tcpSeqBase() + r.tcpBytes.Load() + fakeSeqGap + uint32(i)
	}
	return r.seq.Load() + fakeSeqGap + uint32(i)
}

func (r *Raw) sendFakes(to *net.IPAddr) {
	if !r.desync.on || to == nil {
		return
	}
	fd := r.fakeFd
	src, dst := r.srcIP(), to.IP
	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], to.IP.To4())
	for i, sp := range r.desync.specs() {
		dseq := r.decoySeq(i)
		var dack uint32
		if r.proto == protoTCP {
			dack = r.tcpAck.Load()
		}
		fsrv, fcli := r.wirePorts(r.cport())
		body := rawEncap(r.profile, fakePayload(), src, dst, r.isClient, r.icmpID, fsrv, fcli,
			dseq, dack, r.spi, r.tsNow(), r.tsEcr.Load(), tcpPshAck)
		out := buildIP4Ext(src, dst, r.proto, sp.ttl, sp.badSum, body)
		if out == nil {
			continue
		}
		if sp.badSum {
			if r.inj != nil {
				r.dsSend.note("raw", r.inj.sendTo(to.IP, out))
			}
			continue
		}
		if fd < 0 {
			continue
		}
		r.sendMu.RLock()
		if !r.sendDown {
			r.dsSend.note("raw", syscall.Sendto(fd, out, 0, &sa))
		}
		r.sendMu.RUnlock()
	}
}

func newRaw(conn *net.IPConn, dev *tun.Device, obfs bool, psk, cipher, profile string, isClient bool) *Raw {
	var idb [18]byte
	_, _ = rand.Read(idb[:])
	spi := binary.BigEndian.Uint32(idb[10:14])
	if spi < 256 {
		spi += 256
	}

	icmpID := binary.BigEndian.Uint16(idb[0:2])
	if profile == "icmp" {
		h := sha256.Sum256([]byte("tnl-core|v2|icmp-id|" + psk))
		icmpID = binary.BigEndian.Uint16(h[0:2])
	}
	r := &Raw{
		conn: conn, batch: batchConn(conn), dev: dev, obfs: obfs, ping: pingEvery,
		psk: psk, cipher: cipher, profile: profile, isClient: isClient, fakeFd: -1,
		icmpID: icmpID, closeCh: make(chan struct{}), wake: make(chan struct{}, 1), spi: spi,
	}

	r.rxw = newTunWriters([]*tun.Device{dev})
	r.txq = []txQueue{{dev: dev, batch: r.batch}}
	r.newTCPFlow()
	return r
}

func (r *Raw) newTCPFlow() {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return
	}
	r.tcpISN.Store(binary.BigEndian.Uint32(b[0:4]))
	r.tcpAck.Store(binary.BigEndian.Uint32(b[4:8]))
	r.peerSeen.Store(false)
	r.synAcked.Store(false)
	r.tsBase.Store(binary.BigEndian.Uint32(b[8:12]))
	r.tsStart.Store(time.Now().UnixNano())
	r.tcpBytes.Store(0)
}

func (r *Raw) tcpSeqBase() uint32 { return r.tcpISN.Load() + 1 }

func (r *Raw) notePeerSeq(next uint32, first bool) {
	for {
		cur := r.tcpAck.Load()
		if !first && r.peerSeen.Load() && int32(next-cur) <= 0 {
			return
		}
		if r.tcpAck.CompareAndSwap(cur, next) {
			r.peerSeen.Store(true)
			return
		}
	}
}

func (r *Raw) sendTCPFlags(flags byte, to *net.IPAddr, cport uint16) {
	if to == nil || r.proto != protoTCP {
		return
	}
	seq := r.tcpISN.Load()
	if flags&tcpSyn == 0 {
		seq = r.tcpSeqBase() + r.tcpBytes.Load()
	}
	srv, cli := r.wirePorts(cport)
	seg := rawEncap(r.profile, nil, r.srcIP(), to.IP, r.isClient, r.icmpID, srv, cli,
		seq, r.tcpAck.Load(), r.spi, r.tsNow(), r.tsEcr.Load(), flags)
	r.writeOut(seg, to)
}

func (r *Raw) knockTCP(to *net.IPAddr) {
	if r.proto != protoTCP || !r.isClient || r.synAcked.Load() {
		return
	}
	r.sendTCPFlags(tcpSyn, to, r.cport())
}

func (r *Raw) tcpFlow(raw []byte, addr *net.IPAddr) bool {
	if r.proto != protoTCP {
		return false
	}
	tcp := tcpOf(raw, r.proto)
	if tcp == nil {
		return false
	}
	flags := tcp[13]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	off := int(tcp[12]>>4) * 4
	switch {
	case flags&tcpSyn != 0 && flags&tcpAckBit == 0:
		if r.isClient {
			return true
		}
		if !r.cliSynOK.Load() || r.cliSyn.Load() != seq {
			r.cliSyn.Store(seq)
			r.cliSynOK.Store(true)
			r.newTCPFlow()
			r.notePeerSeq(seq+1, true)
		}
		r.learnClientPort(binary.BigEndian.Uint16(tcp[0:2]))
		r.sendTCPFlags(tcpSynAck, addr, r.cport())
		return true
	case flags&tcpSyn != 0:
		if !r.isClient {
			return true
		}
		r.notePeerSeq(seq+1, true)
		r.synAcked.Store(true)
		r.sendTCPFlags(tcpAckBit, addr, r.cport())
		return true
	}
	if n := len(tcp) - off; n > 0 && off >= 20 && off <= len(tcp) {
		r.notePeerSeq(seq+uint32(n), false)
	}
	return false
}

func (r *Raw) tsNow() uint32 {
	v := r.tsBase.Load() + uint32(time.Since(time.Unix(0, r.tsStart.Load()))/time.Millisecond)
	if v == 0 {
		v = 1
	}
	return v
}

func dialRawBase(peerIP string, dev *tun.Device, obfs bool, psk, cipher, profile string, rawProto, rawPort int) (*Raw, error) {
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
	applyConnSockBuf(conn)
	r := newRaw(conn, dev, obfs, psk, cipher, profile, true)
	r.proto, r.port = proto, rawPortOr(rawPort)
	r.soloPeer.Store(&net.IPAddr{IP: ip})
	if lip := routeLocalIP(ip); lip != nil {
		r.localIP.Store(&net.IPAddr{IP: lip})
	}
	return r, nil
}

func listenRawBase(listenIP string, dev *tun.Device, obfs bool, psk, cipher, profile string, rawProto, rawPort int) (*Raw, error) {
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

	if err := enablePktinfoDst(conn); err != nil {
		log.Printf("raw: WARNING IP_PKTINFO could not be enabled (%v) — replies will leave from the kernel-default source; a destination-rotation pool will burn every IP except that one", err)
	}
	r := newRaw(conn, dev, obfs, psk, cipher, profile, false)
	r.proto, r.port = proto, rawPortOr(rawPort)
	return r, nil
}

func DialRaw(peerIP string, dev *tun.Device, obfs bool, psk, cipher, profile string, fec bool, fecData, fecParity, rawProto, rawPort, rawSport int, sportRandom bool, rot SportRotation, extraQ ...*tun.Device) (*Raw, error) {
	r, err := dialRawBase(peerIP, dev, obfs, psk, cipher, profile, rawProto, rawPort)
	if err != nil {
		return nil, err
	}
	r.link = &directLink{r: r}

	r.setSportMode(sportRandom, rawSport)
	r.setSportRotate(rot)
	r.initFec(fec, fecData, fecParity)
	r.wireAntiLeak()
	r.rxw = newTunWriters(append([]*tun.Device{dev}, extraQ...))
	if err := r.buildTxQueues(extraQ, r.proto); err != nil {
		r.Close()
		return nil, err
	}
	r.logTxQueues()
	return r, nil
}

func ListenRaw(listenIP string, dev *tun.Device, obfs bool, psk, cipher, profile string, fec bool, fecData, fecParity, rawProto, rawPort, rawSport int, sportRandom bool, rot SportRotation, extraQ ...*tun.Device) (*Raw, error) {
	r, err := listenRawBase(listenIP, dev, obfs, psk, cipher, profile, rawProto, rawPort)
	if err != nil {
		return nil, err
	}
	r.link = &directLink{r: r}
	r.setSportMode(sportRandom, rawSport)
	r.setSportRotate(rot)
	applyConnSockBuf(r.conn)
	r.initFec(fec, fecData, fecParity)
	r.wireAntiLeak()
	r.rxw = newTunWriters(append([]*tun.Device{dev}, extraQ...))
	if err := r.buildTxQueues(extraQ, r.proto); err != nil {
		r.Close()
		return nil, err
	}
	r.logTxQueues()
	return r, nil
}

func (r *Raw) initFec(fec bool, fecData, fecParity int) {
	r.fecEnc, r.fecDec = newFecPair(fec, fecData, fecParity, r.psk, "raw",
		func(pkt []byte) {
			if p := r.dst(); p != nil {
				r.writeOut(r.wire(pkt, p.IP), p)
			}
		},
		func(frame []byte) { r.deliver(frame, r.rxAddr.Load(), uint16(r.rxSport.Load())) })
}

func (r *Raw) Run() error {
	errc := make(chan error, len(r.txq)+1)

	for i := range r.txq {
		q := &r.txq[i]
		go func() { errc <- r.tunToNet(q) }()
	}
	go func() { errc <- r.link.recvLoop() }()
	if r.isClient {
		r.st.trackPath(r.livePath, r.closeCh)
		go r.clientLoop()
	}
	return <-errc
}

func (r *Raw) Close() error {
	r.closeOnce.Do(func() { close(r.closeCh) })
	if r.fecEnc != nil {
		r.fecEnc.Close()
	}

	r.sendMu.Lock()
	r.sendDown = true
	r.sendMu.Unlock()
	r.leak.teardown()
	r.link.close()
	if r.fakeFd >= 0 {
		syscall.Close(r.fakeFd)
	}
	if r.inj != nil {
		r.inj.close()
	}
	r.rxw.close()
	r.closeTxQueues()
	return r.conn.Close()
}

func (r *Raw) sealer() Sealer {
	if box := r.session.Load(); box != nil {
		return box.s
	}
	return nil
}

func (r *Raw) srcIP() net.IP {
	if rs := r.replySrc.Load(); rs != nil {
		return *rs
	}
	if l := r.localIP.Load(); l != nil {
		return l.IP
	}
	return net.IPv4zero
}

func (r *Raw) body(typ byte, payload []byte) ([]byte, error) {
	return sealBody(r.sealer(), r.obfs, typ, payload, padMaxFor(typ))
}

func (r *Raw) wire(body []byte, dst net.IP) []byte { return r.wireTo(body, dst, r.cport()) }

func (r *Raw) wireTo(body []byte, dst net.IP, cport uint16) []byte {
	var seq, ack uint32
	if r.proto == protoTCP {
		n := uint32(len(body))
		seq = r.tcpSeqBase() + r.tcpBytes.Add(n) - n
		ack = r.tcpAck.Load()
	} else {
		seq = r.seq.Add(1)
	}
	srv, cli := r.wirePorts(cport)
	return rawEncap(r.profile, body, r.srcIP(), dst, r.isClient, r.icmpID, srv, cli,
		seq, ack, r.spi, r.tsNow(), r.tsEcr.Load(), tcpPshAck)
}

func (r *Raw) writeOut(pkt []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	r.link.send(pkt, to)
}

func (r *Raw) boundSrc() net.IP {
	if rs := r.replySrc.Load(); rs != nil {
		return *rs
	}
	if r.sp != nil {
		if l := r.localIP.Load(); l != nil {
			return l.IP
		}
	}
	return nil
}

func (r *Raw) replyAddr(addr *net.IPAddr) *net.IPAddr {
	return addr
}

const ipFlagDF = 1 << 14

var ipIDCounter atomic.Uint32

func init() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	ipIDCounter.Store(binary.BigEndian.Uint32(b[:]))
}

func nextIPID() uint16 {
	if id := uint16(ipIDCounter.Add(1)); id != 0 {
		return id
	}
	return uint16(ipIDCounter.Add(1))
}

func buildIP4(src, dst net.IP, proto int, payload []byte) []byte {
	return buildIP4Ext(src, dst, proto, 64, false, payload)
}

func buildIP4Ext(src, dst net.IP, proto, ttl int, badSum bool, payload []byte) []byte {
	if len(payload) > 0xffff-20 {
		return nil
	}
	if ttl < 1 {
		ttl = 1
	} else if ttl > 255 {
		ttl = 255
	}
	h := make([]byte, 20+len(payload))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))

	binary.BigEndian.PutUint16(h[4:6], nextIPID())
	binary.BigEndian.PutUint16(h[6:8], ipFlagDF)
	h[8] = byte(ttl)
	h[9] = byte(proto)
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	sum := onesComplementSum(h[:20])
	binary.BigEndian.PutUint16(h[10:12], sum)
	if badSum {
		binary.BigEndian.PutUint16(h[10:12], ^sum)
		if onesComplementSum(h[:20]) == 0 {
			binary.BigEndian.PutUint16(h[10:12], ^sum^0x0001)
		}
	}
	copy(h[20:], payload)
	return h
}

const ethPIP = 0x0800

func openHdrincl(proto int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return -1, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	applyFdSndBuf(fd, wantSockBuf())
	return fd, nil
}

const rawSendMark = 0x746e6c01

type rawLeak struct {
	peer      net.IP
	profile   string
	port      uint16
	dports    []uint16
	isClient  bool
	marked    bool
	portsMove bool
}

func inSportBand(p uint16) bool {
	return int(p) >= sportBandLo && int(p) < sportBandLo+sportBandSpan
}

func (l rawLeak) heardFrom() []string {
	srv, _ := rawPorts(false, l.port, 0)
	if !l.portsMove {
		return []string{strconv.Itoa(int(srv))}
	}
	out := []string{strconv.Itoa(sportBandLo) + ":" + strconv.Itoa(sportBandLo+sportBandSpan-1)}
	if !inSportBand(srv) {
		out = append(out, strconv.Itoa(int(srv)))
	}
	return out
}

func (l rawLeak) answeredOn() []string {
	if len(l.dports) < 2 {
		srv, _ := rawPorts(false, l.port, 0)
		return []string{strconv.Itoa(int(srv))}
	}
	out := make([]string, 0, len(l.dports))
	for _, p := range l.dports {
		out = append(out, strconv.Itoa(int(p)))
	}
	return out
}

func rawDropMatches(l rawLeak) [][]string {
	d := l.peer.String()
	switch l.profile {
	case "icmp":
		if l.isClient || !l.marked {
			return nil
		}
		return [][]string{{"-d", d, "-p", "icmp", "--icmp-type", "echo-reply",
			"-m", "mark", "!", "--mark", fmt.Sprintf("%#x", rawSendMark)}}
	case "udp":
		return [][]string{{"-d", d, "-p", "icmp", "--icmp-type", "port-unreachable"}}
	case "tcp":
		side, specs := "--dport", l.heardFrom()
		if !l.isClient {
			side, specs = "--sport", l.answeredOn()
		}
		out := make([][]string, 0, len(specs))
		for _, spec := range specs {
			out = append(out, []string{"-d", d, "-p", "tcp", side, spec, "--tcp-flags", "RST", "RST"})
		}
		return out
	}

	return nil
}

func addRawDrop(l rawLeak, tun string) (func(), bool) {
	type installed struct {
		match, owner []string
	}
	var added []installed
	want := rawDropMatches(l)
	for _, m := range want {
		args := append([]string{"-I", "OUTPUT"}, append(append([]string{}, m...), "-j", "DROP")...)
		own, ok := runRule(args, ownerMatch(tun), "raw: anti-leak")
		if !ok {
			continue
		}
		added = append(added, installed{m, own})
	}
	if len(added) == 0 {
		return nil, len(want) == 0
	}
	log.Printf("raw: anti-leak scoped to %s (%d OUTPUT rule(s), profile %s, owner %s)", l.peer, len(added), l.profile, ownerLabel(added[0].owner, tun))
	return func() {
		for _, in := range added {
			del := append([]string{"-D", "OUTPUT"}, append(append([]string{}, in.match...), "-j", "DROP")...)
			delRule(append(del, in.owner...), "raw: anti-leak")
		}
	}, len(added) == len(want)
}

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

func (r *Raw) cport() uint16 { return uint16(r.cliPort.Load()) }

func (r *Raw) rotActive() bool { return r.sportEvery > 0 }

func (r *Raw) portsMove() bool { return r.rotActive() || r.sportRandom }

func (r *Raw) portStepAt(sent uint64) uint64 {
	if r.rotActive() {
		return uint64(r.rotIdx) + sent/uint64(r.sportEvery)
	}
	return uint64(r.rotIdx) + r.portEpoch.Load()
}

func (r *Raw) portStep() uint64 {
	if !r.rotActive() {
		return r.portStepAt(0)
	}
	return r.portStepAt(r.txCount.Add(1) - 1)
}

func (r *Raw) portStepNow() uint64 {
	sent := r.txCount.Load()
	if sent > 0 {
		sent--
	}
	return r.portStepAt(sent)
}

func (r *Raw) dportAt(w uint64) uint16 {
	if len(r.dports) < 2 {
		return r.port
	}
	return r.dports[(w/sportBandSpan)%uint64(len(r.dports))]
}

func (r *Raw) portsAt(w uint64, cport uint16) (uint16, uint16) {
	if !r.isClient {
		return r.rotPerm.at(w), cport
	}
	if r.rotActive() {
		cport = r.rotPerm.at(w)
	}
	return r.dportAt(w), cport
}

func (r *Raw) wirePorts(cport uint16) (uint16, uint16) {
	if !r.portsMove() {
		return r.port, cport
	}
	return r.portsAt(r.portStep(), cport)
}

func (r *Raw) wirePortsNow() (uint16, uint16) {
	if !r.portsMove() {
		return r.port, r.cport()
	}
	return r.portsAt(r.portStepNow(), r.cport())
}

func (r *Raw) rotSnapshot() rotStatus {
	if !r.portsMove() {
		return rotStatus{}
	}
	w := r.portStepNow()
	srv, cli := r.portsAt(w, r.cport())
	sport, dport := rawPorts(r.isClient, srv, cli)
	return rotStatus{Sport: sport, Dport: dport, Dports: len(r.dports), Every: r.sportEvery,
		Lo: sportBandLo, Hi: sportBandLo + sportBandSpan - 1, Drawn: w - uint64(r.rotIdx) + 1}
}

func (r *Raw) armWalk() {
	r.rotIdx = randBelow(sportBandSpan)
	r.rotPerm = rotPermFrom(r.psk, r.isClient)
}

func (r *Raw) setSportRotate(rot SportRotation) {
	if rot.Every <= 0 || !RawProfileHasPorts(r.profile) {
		return
	}
	r.sportEvery = rot.Every
	r.armWalk()
	r.dports = dportSet(r.port, rot.Dports, r.psk)
}

func (r *Raw) setSportMode(on bool, fix int) {
	r.sportRandom = on && RawProfileHasPorts(r.profile)
	if RawProfileHasPorts(r.profile) && fix > 0 && fix <= 65535 && !r.sportRandom {
		r.cliPort.Store(uint32(fix))
	}
	if !r.sportRandom {
		return
	}
	r.armWalk()
	if r.isClient {
		r.cliPort.Store(uint32(r.rotPerm.at(r.portStepNow())))
	}
}

func (r *Raw) learnClientPort(sport uint16) {
	if r.isClient || sport == 0 || !RawProfileHasPorts(r.profile) {
		return
	}
	if prev := uint16(r.cliPort.Swap(uint32(sport))); prev != 0 && prev != sport && r.sportRandom {
		r.portEpoch.Add(1)
	}
}

func (r *Raw) replyPort(sport uint16) uint16 {
	if r.isClient || sport == 0 || !RawProfileHasPorts(r.profile) {
		return r.cport()
	}
	return sport
}

func (r *Raw) usePort() {
	r.unanswered.Store(true)
	r.ci.Store(nil)
	if r.sportRandom {
		r.portEpoch.Add(1)
		r.cliPort.Store(uint32(r.rotPerm.at(r.portStepNow())))
	}
	r.newTCPFlow()
}

func (r *Raw) freshTuple() {
	r.usePort()
	wakeLoop(r.wake)
}

func (r *Raw) mustKnock() bool {
	return handshakeOutstanding(r.sealer(), &r.ci) || r.unanswered.Load()
}

func (r *Raw) rollSourcePort() bool {
	r.usePort()
	r.sendInit()

	r.st.portRedrawn()
	wakeLoop(r.wake)
	return true
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
	r.leak.init(r.closeCh, func(peer net.IP) (func(), bool) {
		return addRawDrop(rawLeak{peer: peer, profile: r.profile, port: r.port, dports: r.dports,
			isClient: r.isClient, marked: marked, portsMove: r.portsMove()}, r.tunName())
	})
	if p := r.dst(); p != nil {
		r.leak.scope(p.IP)
	}
}

func (r *Raw) tunToNet(q *txQueue) error {
	buf := make([]byte, maxDatagram)

	ms := make([]ipv4.Message, maxBatch)
	for i := range ms {
		ms[i].Buffers = make([][]byte, 1)
	}
	for {
		n, err := q.dev.Read(buf)
		if err != nil {
			return err
		}
		peer := r.dst()
		if peer == nil {
			continue
		}
		if r.sealer() == nil || r.unanswered.Load() {
			continue
		}
		body, err := r.body(typeData, buf[:n])
		if err != nil {
			log.Printf("raw: seal error: %v", err)
			continue
		}
		if r.fecEnc != nil {
			r.fecEnc.addData(body)
			continue
		}
		pkt := r.wire(body, peer.IP)

		if r.canBatch(q) {
			var oob []byte
			if src := r.boundSrc(); src != nil {
				oob = r.srcOOB(src)
			}
			ms[0].Buffers[0], ms[0].Addr, ms[0].OOB = pkt, peer, oob
			n := 1
			for n < maxBatch {
				m, ok, err := q.dev.TryRead(buf)
				if err != nil || !ok {
					break
				}
				b, err := r.body(typeData, buf[:m])
				if err != nil {
					continue
				}
				ms[n].Buffers[0], ms[n].Addr, ms[n].OOB = r.wire(b, peer.IP), peer, oob
				n++
			}
			if n > 1 {
				if sent := sendBatch(q.batch, ms[:n]); sent != n {
					r.sendErr.note("raw/batch", errShortBatch)
				}
				continue
			}
		}
		r.writeOut(pkt, peer)
	}
}

func (r *Raw) canBatch(q *txQueue) bool {
	return q.batch != nil && r.fecEnc == nil
}

func (r *Raw) recvConnLoop() error {
	b := newRecvBatcher(maxRecvBatch)
	for {
		ms, err := b.recv(r.batch)
		if err != nil {
			return err
		}
		for i := range ms {
			m := &ms[i]
			addr, _ := m.Addr.(*net.IPAddr)
			if addr == nil {
				continue
			}
			if peer := r.dst(); peer != nil && !addr.IP.Equal(peer.IP) && !r.srcAllowed(addr.IP) {
				continue
			}
			if !r.isClient {
				r.learnReplySrc(m.OOB[:m.NN])
			}
			r.handleRaw(m.Buffers[0][:m.N], addr)
		}
	}
}

func (r *Raw) learnReplySrc(oob []byte) {
	var d net.IP
	if len(oob) > 0 {
		d = pktinfoDst(oob)
	}
	switch {
	case d == nil:
		r.noPktinfo.Do(func() {
			log.Printf("raw: WARNING inbound frames carry no IP_PKTINFO — replies will leave from the kernel-default source; a destination-rotation pool will burn every IP except that one")
		})
	case sameIP4(r.replySrc.Load(), d):
	case r.ours.has(d):
		cp := append(net.IP(nil), d...)
		r.replySrc.Store(&cp)
	default:
		r.notOurDst.Do(func() {
			log.Printf("raw: a frame was addressed to %s, which is not an address this host holds — not answering from it", d)
		})
	}
}

func (r *Raw) handleRaw(raw []byte, addr *net.IPAddr) {
	if r.tcpFlow(raw, addr) {
		return
	}
	body, sport, pts, ok := rawDecap(r.profile, r.proto, raw)
	if !ok {
		return
	}
	if pts != 0 {
		r.tsEcr.Store(pts)
	}
	if r.fecDec != nil {
		r.rxAddr.Store(addr)
		r.rxSport.Store(uint32(sport))
		r.fecDec.input(body)
		return
	}
	r.deliver(body, addr, sport)
}

func (r *Raw) deliver(body []byte, addr *net.IPAddr, sport uint16) {
	if addr == nil {
		return
	}
	r.handleCrypto(body, addr, sport)
}

func (r *Raw) openWith(s Sealer, body []byte) (typ byte, session, seq uint64, payload []byte, oerr error) {
	return openFrame(s, body, r.obfs)
}

func (r *Raw) handleCrypto(body []byte, addr *net.IPAddr, sport uint16) {
	if s := r.sealer(); s != nil {
		if typ, session, seq, payload, oerr := r.openWith(s, body); oerr == nil && r.rp.ok(session, seq) {
			settleHandshake(&r.ci)
			r.unanswered.Store(false)
			r.markRx(addr.IP)
			r.provenFrom(addr.IP)
			r.learnPeer(addr)
			r.learnClientPort(sport)
			r.dispatch(typ, payload, addr)
			return
		}
	}

	for _, st := range r.staged {
		if typ, session, seq, payload, oerr := r.openWith(st.box.s, body); oerr == nil && st.rp.ok(session, seq) {
			r.session.Store(st.box)
			r.fecDec.reset()
			r.rp = st.rp
			r.staged = nil
			r.markRx(addr.IP)
			r.learnPeer(addr)
			r.learnClientPort(sport)
			r.dispatch(typ, payload, addr)
			return
		}
	}
	r.tryHandshake(body, addr, sport)
}

func (r *Raw) learnPeer(addr *net.IPAddr) {
	if r.pp == nil {
		r.soloPeer.Store(addr)
	}
	r.learnLocalIP(addr.IP)

	if p := r.dst(); p != nil {
		r.leak.scopeAsync(p.IP)
	}
}

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
		r.fecDec.reset()

		r.ci.Store(nil)
		r.unanswered.Store(false)
		r.markRx(addr.IP)
		r.provenFrom(addr.IP)
		r.st.newSession()
		r.st.reconnected("raw")
		return
	}

	if len(r.staged) > 0 {
		if resp, ok := r.hsCache.get(body); ok {
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

	r.staged = stageSession(r.staged, s)
	r.learnLocalIP(addr.IP)

	r.learnClientPort(hsSport)

	if r.dst() == nil {
		r.leak.scopeAsync(addr.IP)
	}
	if msg2 := crypto.RespMsg(r.psk, eInit, sr); msg2 != nil {
		r.hsCache.put(body, msg2)
		r.writeCtrlTo(msg2, r.replyAddr(addr), r.replyPort(hsSport))
	}
}

func (r *Raw) writeCtrl(body []byte, to *net.IPAddr) { r.writeCtrlTo(body, to, r.cport()) }

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
	case typeData:
		r.rxw.write(payload)
	}
}

func (r *Raw) livePath() (pathKey, bool) {
	k := pathKey{Src: r.srcIP().String()}
	if p := r.dst(); p != nil {
		k.Dst = p.IP.String()
	}
	if RawProfileHasPorts(r.profile) && !r.rotActive() {
		srv, cli := r.wirePortsNow()
		k.Sport, k.Dport = rawPorts(r.isClient, srv, cli)
	}
	return k, r.sealer() != nil
}

func (r *Raw) rehandshake() bool {
	if r.dst() == nil {
		return false
	}
	r.ci.Store(nil)
	r.sendInit()
	r.st.down("rehandshake", "raw")
	wakeLoop(r.wake)
	return true
}

func (r *Raw) markRx(from net.IP) {
	if p := r.dst(); p != nil && from != nil && p.IP.Equal(from) {
	}
}

func (r *Raw) provenFrom(ip net.IP) {
	if ip != nil && len(r.poolIPs) > 0 {
		if p := r.dst(); p != nil && !p.IP.Equal(ip) {
			if v4 := ip.To4(); v4 != nil {
				if _, other := r.poolIPs[string(v4)]; other {
					return
				}
			}
		}
	}
	r.peerAnswered.Store(true)
}

func (r *Raw) SetPeerPool(pp *PeerPool) {
	if r.isClient {
		r.pp = pp
		if pp != nil {
			joinStatus(r.st, pp, "dst")

			m := buildSrcAllow(pp.all())
			r.poolIPs = m
			if len(m) > 0 {
				r.srcAllow = m
			}
		}
	}
}

func (r *Raw) SetPeerSources(ips []string) {
	if r.isClient || len(ips) == 0 {
		return
	}
	if m := buildSrcAllow(ips); len(m) > 0 {
		r.srcAllow = m
	}
	r.leak.scopeAll(parseIP4s(ips))
}

func (r *Raw) srcAllowed(ip net.IP) bool {
	return srcAllowedIn(r.srcAllow, ip)
}

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

func (r *Raw) SetSourcePool(sp *PeerPool) {
	if !r.isClient {
		return
	}
	r.sp = sp

	if sp != nil {
		joinStatus(r.st, sp, "src")
		if ip := adoptableSource("raw", sp.current(), &r.srcWarned); ip != nil {
			r.localIP.Store(&net.IPAddr{IP: ip})
		} else {
			sp.fail("unbindable")
		}
	}
}

func (r *Raw) rotateSourceRaw(proactive bool) {
	if r.sp == nil {
		return
	}
	prev := r.sp.current()
	addr, moved := r.sp.nextEndpoint(proactive)
	if !moved {
		return
	}
	ip := adoptableSource("raw", addr, &r.srcWarned)
	if ip == nil {
		r.sp.rejectCandidate(prev)
		return
	}
	r.localIP.Store(&net.IPAddr{IP: ip})
	r.freshTuple()
	log.Printf("raw: rotated source to %s", addr)

	r.st.rotated("src", "ip:"+addr, proactive)
}

func (r *Raw) rotatePeerRaw(proactive bool) {
	if r.pp == nil {
		return
	}
	addr, moved := r.pp.nextEndpoint(proactive)
	if !moved {
		return
	}
	if r.landPeerRaw(!proactive) == nil {
		return
	}
	log.Printf("raw: rotated destination to %s", addr)
	r.st.rotated("peer", "ip:"+addr, proactive)
	if proactive {
		return
	}
	wakeLoop(r.wake)
}

func (r *Raw) dst() *net.IPAddr {
	if r.pp != nil {
		if a := r.pp.liveAddr(); a != nil {
			return a.ip
		}
		return nil
	}
	return r.soloPeer.Load()
}

func (r *Raw) landPeerRaw(hard bool) *net.IPAddr {
	pa := r.dst()
	if pa == nil {
		return nil
	}
	r.freshTuple()
	r.leak.scope(pa.IP)
	r.st.setActive("raw:" + r.profile + " · " + pa.IP.String())
	if hard {
		r.session.Store(nil)
		r.ci.Store(nil)
	}
	r.peerAnswered.Store(false)
	return pa
}

func (r *Raw) selectedRaw(kind, _ string) {
	if kind == "src" {
		r.adoptSourceRaw()
		return
	}
	r.adoptPeerRaw()
}

func (r *Raw) adoptPeerRaw() {
	if r.pp == nil {
		return
	}
	pa := r.landPeerRaw(true)
	if pa == nil {
		return
	}
	log.Printf("raw: destination moved to %s (operator)", pa.IP)
	wakeLoop(r.wake)
}

func (r *Raw) adoptSourceRaw() {
	if r.sp == nil {
		return
	}
	ip := adoptableSource("raw", r.sp.current(), &r.srcWarned)
	if ip == nil {
		r.sp.fail("unbindable")
		return
	}
	prevSrc := r.localIP.Load()
	r.localIP.Store(&net.IPAddr{IP: ip})
	if prevSrc == nil || !prevSrc.IP.Equal(ip) {
		r.freshTuple()
	}
	log.Printf("raw: source moved to %s (operator)", ip)
}

func (r *Raw) cmdPollLoop(rc *rotationController) {
	runCmdPoll(rc, r.closeCh, r.selectedRaw, r.rotatePeerRaw, r.rotateSourceRaw, r.st.pathEpoch)
}

func (r *Raw) clientLoop() {
	rc := newRotationController(r.pp, r.sp)
	rc.session.setDrop(r.rehandshake)

	if r.sportRandom {
		rc.port.setRoll(r.rollSourcePort)
	}
	rc.attachStatus(r.st)
	r.st.setPair(rc.pairStatus)
	if rc.polls() {
		go r.cmdPollLoop(rc)
	}

	for {
		rc.proactive(r.rotatePeerRaw, r.rotateSourceRaw, time.Now())
		asking := r.mustKnock()
		if asking {
			r.sendInit()
		}
		if r.sealer() != nil {
			r.send(typePing, nil, r.dst())

			if r.sealer() == nil {
				continue
			}
		}
		wait := keepaliveInterval(r.ping, r.psk)
		if asking {
			wait = handshakeRetransmitWait()
		}
		select {
		case <-r.closeCh:
			return
		case <-r.wake:
		case <-time.After(wait):
		}
	}
}

func (r *Raw) sendInit() {
	peer := r.dst()
	if peer == nil {
		return
	}
	r.knockTCP(peer)

	ci := r.ci.Load()
	if ci == nil {
		var err error
		if ci, err = crypto.GenerateEphemeral(); err != nil {
			return
		}
		r.ci.Store(ci)

		r.sendFakes(peer)
	}
	r.writeCtrl(crypto.InitMsg(r.psk, ci), peer)
}

func (r *Raw) send(typ byte, payload []byte, to *net.IPAddr) {
	if to == nil {
		return
	}
	if r.sealer() == nil {
		return
	}
	body, err := r.body(typ, payload)
	if err != nil {
		return
	}
	r.writeCtrl(body, to)
	if typ == typePing {
	}
}

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
