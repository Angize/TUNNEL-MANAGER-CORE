package dnstun

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	pollInterval = 40 * time.Millisecond
	queryTimeout = 3 * time.Second

	serverHold = 150 * time.Millisecond
)

var (
	pipelineWindow  = 16
	idleTarget      = 2
	sweepInterval   = 500 * time.Millisecond
	collapseEmpties = 24
)

const serverWorkers = 24

const dnsReadBuf = 1500

func newNonce() string {
	var b [(nonceLen*5 + 7) / 8]byte
	_, _ = rand.Read(b[:])
	return lowB32.EncodeToString(b[:])[:nonceLen]
}

func buildQuery(id uint16, name string) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions:   []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{ednsOPT()},
	}
	return msg.Pack()
}

func parseResponseTXT(buf []byte, wantID uint16) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil {
		return nil, err
	}
	if h.ID != wantID || !h.Response {
		return nil, errors.New("dns: response id/flag mismatch")
	}

	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns: resolver returned %v", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []byte
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if ah.Type == dnsmessage.TypeTXT {
			txt, terr := p.TXTResource()
			if terr != nil {
				return nil, terr
			}
			for _, s := range txt.TXT {
				out = append(out, s...)
			}
		} else if err := p.SkipAnswer(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func parseMsgQuestion(buf []byte, wantResponse bool) (id uint16, name string, qtype dnsmessage.Type, ok bool) {
	var p dnsmessage.Parser
	h, err := p.Start(buf)
	if err != nil || h.Response != wantResponse {
		return 0, "", 0, false
	}
	q, err := p.Question()
	if err != nil {
		return 0, "", 0, false
	}
	return h.ID, q.Name.String(), q.Type, true
}

func parseQuery(buf []byte) (id uint16, name string, qtype dnsmessage.Type, ok bool) {
	return parseMsgQuestion(buf, false)
}

const ednsUDPSize = 1232

func ednsOPT() dnsmessage.Resource {
	var h dnsmessage.ResourceHeader
	_ = h.SetEDNS0(ednsUDPSize, dnsmessage.RCodeSuccess, false)
	return dnsmessage.Resource{Header: h, Body: &dnsmessage.OPTResource{}}
}

func buildResponse(id uint16, qname dnsmessage.Name, qtype dnsmessage.Type, answers, authority []dnsmessage.Resource) ([]byte, error) {
	msg := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, Response: true, Authoritative: true},
		Questions:   []dnsmessage.Question{{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}},
		Answers:     answers,
		Authorities: authority,
		Additionals: []dnsmessage.Resource{ednsOPT()},
	}
	return msg.Pack()
}

func txtResource(name dnsmessage.Name, txt []string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.TXTResource{TXT: txt},
	}
}

type dnsClient struct {
	conn      *net.UDPConn
	resolvers []*net.UDPAddr
	rr        atomic.Uint32
	codec     *Codec
	outbound  chan []byte
	inbound   chan []byte
	closed    chan struct{}
	once      sync.Once
	qid       atomic.Uint32
	sendErr   sendErrLog
	answerErr sendErrLog

	mu       sync.Mutex
	inflight map[uint16]inflightQuery
	slots    chan struct{}
	active   atomic.Bool
	wake     chan struct{}
	wg       sync.WaitGroup
}

type inflightQuery struct {
	deadline time.Time
	nonce    string
}

func NewDNSClientTransport(resolverAddrs []string, codec *Codec) (WireTransport, error) {
	var resolvers []*net.UDPAddr
	for _, ra := range resolverAddrs {
		ra = strings.TrimSpace(ra)
		if ra == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(ra); err != nil {
			host := strings.TrimSuffix(strings.TrimPrefix(ra, "["), "]")
			ra = net.JoinHostPort(host, "53")
		}
		ua, err := net.ResolveUDPAddr("udp", ra)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, ua)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("dns: no usable resolver configured")
	}
	laddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	c := &dnsClient{
		conn:      conn,
		resolvers: resolvers,
		codec:     codec,
		outbound:  make(chan []byte, sendQueueSize),
		inbound:   make(chan []byte, recvQueueSize),
		closed:    make(chan struct{}),
		inflight:  make(map[uint16]inflightQuery, pipelineWindow),
		slots:     make(chan struct{}, pipelineWindow),
		wake:      make(chan struct{}, 1),
	}
	for i := 0; i < pipelineWindow; i++ {
		c.slots <- struct{}{}
	}
	c.wg.Add(3)
	go c.sendLoop()
	go c.recvLoop()
	go c.sweepLoop()
	return c, nil
}

func queueSend(closed <-chan struct{}, q chan<- []byte, d []byte) error {
	select {
	case <-closed:
		return net.ErrClosed
	default:
	}
	buf := append([]byte(nil), d...)
	select {
	case q <- buf:
	default:
	}
	return nil
}

func queueRecv(in <-chan []byte, closed <-chan struct{}) ([]byte, error) {
	select {
	case d := <-in:
		return d, nil
	case <-closed:
		return nil, net.ErrClosed
	}
}

func (c *dnsClient) Send(d []byte) error { return queueSend(c.closed, c.outbound, d) }

func (c *dnsClient) Recv() ([]byte, error) { return queueRecv(c.inbound, c.closed) }

func (c *dnsClient) Close() error {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
	c.wg.Wait()
	return nil
}

func (c *dnsClient) sendLoop() {
	defer c.wg.Done()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-c.closed:
			return
		case up := <-c.outbound:
			if !c.sendOne(up) {
				return
			}
		case <-c.wake:
			if !c.fill() {
				return
			}
		case <-tick.C:
			if !c.fill() {
				return
			}
		}
	}
}

func (c *dnsClient) fill() bool {
	target := idleTarget
	if c.active.Load() {
		target = pipelineWindow
	}
	for c.inflightLen() < target {
		before := c.inflightLen()
		if !c.sendOne(nil) {
			return false
		}

		if c.inflightLen() <= before {
			break
		}
	}
	return true
}

func (c *dnsClient) sendOne(up []byte) bool {
	if !c.acquire() {
		return false
	}
	nonce := newNonce()
	name, err := c.codec.EncodeName(up, nonce)
	if err != nil {
		c.release()
		return true
	}
	c.mu.Lock()
	var id uint16
	for {
		var idb [2]byte
		if _, rerr := rand.Read(idb[:]); rerr == nil {
			id = uint16(idb[0])<<8 | uint16(idb[1])
		} else {
			id = uint16(c.qid.Add(1))
		}
		if _, dup := c.inflight[id]; !dup {
			break
		}
	}
	c.inflight[id] = inflightQuery{deadline: time.Now().Add(queryTimeout), nonce: nonce}
	c.mu.Unlock()
	query, err := buildQuery(id, name)
	if err != nil {
		c.dropInflight(id)
		return true
	}
	resolver := c.resolvers[int(c.rr.Add(1)-1)%len(c.resolvers)]
	if _, err := c.conn.WriteToUDP(query, resolver); err != nil {
		c.sendErr.note("dns/"+resolver.String(), err)
		c.dropInflight(id)
		return true
	}
	return true
}

func (c *dnsClient) recvLoop() {
	defer c.wg.Done()
	buf := make([]byte, dnsReadBuf)
	empties := 0
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		id, qname, ok := responseIDName(buf[:n])
		if !ok {
			continue
		}
		if !c.matchRelease(id, qname) {
			continue
		}
		down, derr := parseResponseTXT(buf[:n], id)
		if derr != nil {
			c.answerErr.noteAs("dns/"+from.String(), "answer rejected", derr)

			down = nil
		}
		if len(down) > 0 {
			select {
			case c.inbound <- down:
			case <-c.closed:
				return
			default:
			}
			c.active.Store(true)
			empties = 0
		} else if empties++; empties >= collapseEmpties {
			c.active.Store(false)
			empties = 0
		}
	}
}

func (c *dnsClient) sweepLoop() {
	defer c.wg.Done()
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			now := time.Now()
			freed := 0
			c.mu.Lock()
			for id, e := range c.inflight {
				if now.After(e.deadline) {
					delete(c.inflight, id)
					freed++
				}
			}
			c.mu.Unlock()
			for i := 0; i < freed; i++ {
				c.release()
			}
		}
	}
}

func (c *dnsClient) acquire() bool {
	select {
	case <-c.slots:
		return true
	case <-c.closed:
		return false
	}
}

func (c *dnsClient) release() {
	select {
	case c.slots <- struct{}{}:
	default:
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *dnsClient) inflightLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.inflight)
}

func (c *dnsClient) matchRelease(id uint16, qname string) bool {
	c.mu.Lock()
	e, ok := c.inflight[id]
	if ok && strings.EqualFold(nonceLabel(qname), e.nonce) {
		delete(c.inflight, id)
	} else {
		ok = false
	}
	c.mu.Unlock()
	if ok {
		c.release()
	}
	return ok
}

func (c *dnsClient) dropInflight(id uint16) {
	c.mu.Lock()
	_, ok := c.inflight[id]
	if ok {
		delete(c.inflight, id)
	}
	c.mu.Unlock()
	if ok {
		c.release()
	}
}

func responseIDName(buf []byte) (id uint16, qname string, ok bool) {
	id, qname, _, ok = parseMsgQuestion(buf, true)
	return
}

func nonceLabel(qname string) string {
	if i := strings.IndexByte(qname, '.'); i >= 0 {
		return qname[:i]
	}
	return qname
}

type dnsServer struct {
	conn       *net.UDPConn
	codec      *Codec
	upstream   chan []byte
	downstream chan []byte
	closed     chan struct{}
	serveDone  chan struct{}
	once       sync.Once

	sendErr sendErrLog

	soa dnsmessage.Resource
	ns  dnsmessage.Resource
}

func NewDNSServerTransport(listenAddr string, codec *Codec) (WireTransport, net.Addr, error) {
	_, soa, ns, err := apexRecords(codec.Zone())
	if err != nil {
		return nil, nil, err
	}
	la, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, nil, err
	}
	s := &dnsServer{
		conn:       conn,
		codec:      codec,
		upstream:   make(chan []byte, recvQueueSize),
		downstream: make(chan []byte, sendQueueSize),
		closed:     make(chan struct{}),
		serveDone:  make(chan struct{}),
		soa:        soa,
		ns:         ns,
	}
	go s.serveLoop()
	return s, conn.LocalAddr(), nil
}

func apexRecords(zone string) (dnsmessage.Name, dnsmessage.Resource, dnsmessage.Resource, error) {
	zn, err := dnsmessage.NewName(zone)
	if err != nil {
		return dnsmessage.Name{}, dnsmessage.Resource{}, dnsmessage.Resource{}, err
	}
	mbox, err := dnsmessage.NewName("hostmaster." + zone)
	if err != nil {
		mbox = zn
	}
	soa := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: zn, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET},
		Body: &dnsmessage.SOAResource{
			NS: zn, MBox: mbox, Serial: 1,
			Refresh: 3600, Retry: 600, Expire: 604800, MinTTL: 0,
		},
	}
	ns := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: zn, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.NSResource{NS: zn},
	}
	return zn, soa, ns, nil
}

func (s *dnsServer) Send(d []byte) error { return queueSend(s.closed, s.downstream, d) }

func (s *dnsServer) Recv() ([]byte, error) { return queueRecv(s.upstream, s.closed) }

func (s *dnsServer) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
	<-s.serveDone
	return nil
}

func (s *dnsServer) serveLoop() {
	defer close(s.serveDone)
	sem := make(chan struct{}, serverWorkers)
	var wg sync.WaitGroup
	buf := make([]byte, dnsReadBuf)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		id, qname, qtype, ok := parseQuery(buf[:n])
		if !ok {
			continue
		}
		qn, nerr := dnsmessage.NewName(qname)
		if nerr != nil {
			continue
		}

		if qtype != dnsmessage.TypeTXT {
			if !s.underZone(qname) {
				continue
			}
			ans := s.apexAnswers(qname, qtype)
			resp, berr := buildResponse(id, qn, qtype, ans, s.negativeAuthority(ans))
			if berr == nil {
				if _, err := s.conn.WriteToUDP(resp, addr); err != nil {
					s.sendErr.note("dns/apex", err)
				}
			}
			continue
		}

		data, derr := s.codec.DecodeName(qname)
		if errors.Is(derr, ErrBareZone) {
			resp, berr := buildResponse(id, qn, dnsmessage.TypeTXT, nil, s.negativeAuthority(nil))
			if berr == nil {
				if _, err := s.conn.WriteToUDP(resp, addr); err != nil {
					s.sendErr.note("dns/apex", err)
				}
			}
			continue
		}
		if derr != nil {
			continue
		}
		if len(data) > 0 {
			select {
			case s.upstream <- data:
			default:
			}
		}

		ra := *addr
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(id uint16, qn dnsmessage.Name, ra net.UDPAddr) {
				defer wg.Done()
				defer func() { <-sem }()
				s.reply(id, qn, &ra)
			}(id, qn, ra)
		default:
			s.replyNoHold(id, qn, addr)
		}
	}
	wg.Wait()
}

func (s *dnsServer) reply(id uint16, qn dnsmessage.Name, addr *net.UDPAddr) {
	var down []byte
	select {
	case down = <-s.downstream:
	case <-s.closed:
		return
	default:
		hold := time.NewTimer(serverHold)
		select {
		case down = <-s.downstream:
		case <-hold.C:
		case <-s.closed:
			hold.Stop()
			return
		}
		hold.Stop()
	}
	s.write(id, qn, down, addr)
}

func (s *dnsServer) replyNoHold(id uint16, qn dnsmessage.Name, addr *net.UDPAddr) {
	var down []byte
	select {
	case down = <-s.downstream:
	default:
	}
	s.write(id, qn, down, addr)
}

func (s *dnsServer) write(id uint16, qn dnsmessage.Name, down []byte, addr *net.UDPAddr) {
	resp, berr := buildResponse(id, qn, dnsmessage.TypeTXT,
		[]dnsmessage.Resource{txtResource(qn, s.codec.EncodeTXT(down))}, nil)
	if berr != nil {
		return
	}

	if _, err := s.conn.WriteToUDP(resp, addr); err != nil {
		s.sendErr.note("dns/server", err)
	}
}

func (s *dnsServer) apexAnswers(qname string, qtype dnsmessage.Type) []dnsmessage.Resource {
	if !s.isApex(qname) {
		return nil
	}
	switch qtype {
	case dnsmessage.TypeSOA:
		return []dnsmessage.Resource{s.soa}
	case dnsmessage.TypeNS:
		return []dnsmessage.Resource{s.ns}
	}
	return nil
}

func (s *dnsServer) negativeAuthority(answers []dnsmessage.Resource) []dnsmessage.Resource {
	if len(answers) > 0 {
		return nil
	}
	return []dnsmessage.Resource{s.soa}
}

func normName(qname string) string {
	q := strings.ToLower(strings.TrimSpace(qname))
	if !strings.HasSuffix(q, ".") {
		q += "."
	}
	return q
}

func (s *dnsServer) isApex(qname string) bool { return normName(qname) == s.codec.Zone() }

func (s *dnsServer) underZone(qname string) bool {
	q := normName(qname)
	return q == s.codec.Zone() || strings.HasSuffix(q, "."+s.codec.Zone())
}
