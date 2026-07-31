// DNS-tunnel carrier: L3 packets ride a reliable, AEAD-sealed KCP session that is itself tunnelled
// inside DNS queries and responses (see internal/dnstun). The client polls a recursive resolver;
// the server is an authoritative responder. This is the last-resort carrier for a full
// (protocol+destination) whitelist: the client only ever sends UDP/53 to a DOMESTIC resolver — never
// a packet to the foreign server IP — so a destination whitelist cannot see it, and port 53 is kept
// open because blocking it breaks all name resolution. Unlike raw/flux this uses only ordinary UDP
// sockets, so it is portable (no CAP_NET_RAW / Linux-only build).
package packet

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	dnsBackoffMin = time.Second
	dnsBackoffMax = 30 * time.Second
	// dnsMinMTU is the smallest KCP MTU a zone may leave. It is dnstun's number, not a copy: the
	// floor is about KCP's own per-segment overhead, which lives there.
	dnsMinMTU = dnstun.MinUsefulMTU
)

// zoneBytesToDrop is how many characters a zone must lose to free `need` more bytes per query.
// Each raw byte costs ceil(8/5) base32 characters in the query name, so one character of zone buys
// back five eighths of a byte. Reported in the error because "your zone is too long" without a
// number leaves the operator guessing at the one thing they can change.
func zoneBytesToDrop(need int) int { return (need*8 + 4) / 5 }

// DNS carries L3 packets over a DNS tunnel. It satisfies the core carrier interface (Run/Close).
type DNS struct {
	dev       *tun.Device
	isClient  bool
	cfg       dnstun.SessionConfig
	zone      string
	addr      string   // server: listen address (e.g. ":53"); unused for the client
	resolvers []string // client: recursive resolvers to rotate across ("host" or "host:port")

	mu      sync.Mutex // guards curConn/curT so Close can tear down whatever is live
	curConn net.Conn
	curT    dnstun.WireTransport
	conn    atomic.Pointer[net.Conn] // the live session for the long-lived tun→net loop (nil between sessions)

	// Client-only liveness, the same pair every other carrier publishes. hbRx is the unix-nano of the
	// last packet that came OUT of the session — i.e. authenticated, since dnstun opens it under the
	// AEAD sealer — and st republishes it into the status file the node/panel read. Both are nil/zero
	// on the server and until SetStatusPath wires them; coreStatus is nil-safe throughout.
	hbRx atomic.Int64
	st   *coreStatus

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newDNS(dev *tun.Device, isClient bool, addr string, resolvers []string, zone, psk, cipher string, keepalive time.Duration) (*DNS, error) {
	codec, err := dnstun.NewCodec(zone)
	if err != nil {
		return nil, err
	}
	mtu := codec.MaxUpstream() - dnstun.SessionOverhead
	if mtu < dnsMinMTU {
		// The old floor was 40, which kcp-go accepts (it only refuses an MTU at or below its own
		// 24-byte header) — so a long zone came up, logged "session established", and then spent 60%
		// of every DNS query on the KCP header while a single 1200-byte packet shattered into ~75
		// queries. Refusing with the number of characters to remove beats starting a tunnel that
		// cannot carry anything and saying nothing about why.
		return nil, fmt.Errorf("dns: zone %q leaves only %d bytes per query, and the carrier needs %d "+
			"(KCP spends %d of them on its own header) — shorten the zone by about %d characters",
			zone, mtu, dnsMinMTU, dnstun.KCPOverhead, zoneBytesToDrop(dnsMinMTU-mtu))
	}
	return &DNS{
		dev: dev, isClient: isClient, zone: zone, addr: addr, resolvers: resolvers,
		cfg:     dnstun.SessionConfig{PSK: psk, Cipher: cipher, MTU: mtu, Keepalive: keepalive},
		closeCh: make(chan struct{}),
	}, nil
}

// DialDNS (client) tunnels through resolvers (recursive resolvers, each "host" or "host:port",
// typically domestic resolvers on :53) for the delegated zone. Queries rotate across them so heavy
// loss or filtering on one resolver is covered by the others.
func DialDNS(dev *tun.Device, resolvers []string, zone, psk, cipher string, keepalive time.Duration) (*DNS, error) {
	return newDNS(dev, true, "", resolvers, zone, psk, cipher, keepalive)
}

// ListenDNS (server) is the authoritative responder for the delegated zone, bound to listenAddr
// (e.g. ":53"). The server never re-dials, so it takes no keepalive.
func ListenDNS(dev *tun.Device, listenAddr, zone, psk, cipher string) (*DNS, error) {
	return newDNS(dev, false, listenAddr, nil, zone, psk, cipher, 0)
}

// Run drives the carrier: one long-lived tun→net loop feeds whatever session is live, while the
// main loop (re)establishes a session and pumps net→tun until it dies, then reconnects with backoff.

// SetDeadAfter (client) applies the operator's dead_after_secs to the dnstun session's dead window, so
// the fleet-wide setting reaches this carrier like every other one. Previously *DNS simply had no such
// method: main.go probes for it with a type assertion, the assertion failed, and the "self-heal deadline
// set" log line sits inside the successful branch — so the knob was a no-op here with nothing said.
// The session still floors the value, so a tiny setting cannot reap a healthy session.
func (d *DNS) SetDeadAfter(secs int) bool {
	if secs <= 0 {
		return false
	}
	d.cfg.DeadAfter = time.Duration(secs) * time.Second
	// The SERVER of a connectionless carrier holds no dead window at all — there is no connection to
	// reap and clientLoop, the only reader of this value, never starts. Report that rather than let
	// main print "self-heal deadline set to Ns" over a number nothing will ever consult.
	return d.isClient
}

// SetStatusPath (client, optional) wires the status file every OTHER carrier already writes: an
// events ring plus the two numbers a reader needs to age a tunnel — hb (the last authenticated
// inbound frame) and dw (the dead window this carrier really enforces).
//
// dns was the one client carrier with none of it. main.go probes for this method with a type
// assertion, the assertion failed, and the "writing status/events to …" line lives in the successful
// branch — so the file was never created and nothing said why. Downstream that is a dot the panel
// cannot decide: with no hb it has only traffic flow to go on, so a healthy but IDLE dns tunnel ages
// into yellow, and a genuinely dead one never goes red at all, because instant-red is gated on a
// published dead window (_dw > 0) that did not exist. Call before Run().
func (d *DNS) SetStatusPath(path string) {
	if path == "" || !d.isClient {
		return
	}
	d.st = newCoreStatus(path, "dns · "+d.zone)
}

// heartbeat republishes the live session's liveness into the status file, paced off dw exactly as
// the shared heartbeat() does for the other carriers. It is a carrier-local loop only because the
// number has to be PULLED from whatever session is live right now: dns re-dials into a brand new
// session on every recovery, and the shared helper reads one fixed atomic.
//
// The source is the SESSION's lastRx, not the packets this carrier reads. An idle dns tunnel carries
// no data at all — its proof of life is the keepalive pong, which dnstun consumes internally and
// never yields as a packet. Stamping only what netToTun read would freeze hb on a healthy tunnel and
// recreate, from the other side, the exact false-red this whole file is about.
func (d *DNS) heartbeat(dwSecs int64) {
	if d.st == nil {
		return
	}
	t := time.NewTicker(hbPeriod(dwSecs))
	defer t.Stop()
	for {
		if cp := d.conn.Load(); cp != nil {
			// Forward only. Between sessions there is nothing to read, and a fresh session's zero
			// must never drag the published heartbeat backwards into a false death.
			if lc, ok := (*cp).(interface{ LastRx() int64 }); ok {
				if v := lc.LastRx(); v > d.hbRx.Load() {
					d.hbRx.Store(v)
				}
			}
		}
		d.st.beat(d.hbRx.Load() / int64(time.Second))
		select {
		case <-d.closeCh:
			return
		case <-t.C:
		}
	}
}

// deadWin is the window after which a silent session counts as dead. dns does NOT use the shared
// 2×keepalive floor — dnstun applies its own absolute floor, because this carrier is high-loss and
// its window has to survive several dropped polls. Publishing the SAME number the session enforces
// is the point: a reader that re-derived its own multiplier would age hb against a window nothing
// applies (see effectiveDeadAfter, which had that exact bug in the startup log).
//
// It is resolved by ASKING dnstun rather than by restating the rule here, which is what this function
// used to do — and it restated it wrong. It kept the floor and dropped the keepaliveDeadMult×keepalive
// term, so at the shipped defaults it published 20s while the session re-dialled at 45s: a healthy dns
// tunnel went red on the dashboard, and the comment two lines above is exactly the promise it broke.
func (d *DNS) deadWin() time.Duration {
	return dnstun.ResolveDeadWindow(d.cfg.Keepalive, d.cfg.DeadAfter)
}

// DNSDeadFloorSecs is the ABSOLUTE floor (seconds) the dns carrier applies to dead_after_secs — it does
// NOT use the 2×keepalive floor the other carriers do. main.go needs this to log the deadline that will
// really be in force; keeping the lookup here means main.go asks the carrier package rather than
// re-deriving a number that lives in dnstun.
func DNSDeadFloorSecs() int { return int(dnstun.DeadFloor() / time.Second) }

func (d *DNS) Run() error {
	go d.tunToNet()
	if d.isClient {
		dw := int64(d.deadWin().Seconds())
		d.st.setDW(dw) // publish the window a reader must age hb against...
		go d.heartbeat(dw)
	}
	backoff := dnsBackoffMin
	for {
		select {
		case <-d.closeCh:
			return nil
		default:
		}
		conn, err := d.connect()
		if err != nil {
			// Deliberately NO down event here. The retry loop backs off from 1s to 30s, so one per
			// attempt would append an event a second at first and evict the real history out of a
			// capped ring. The session death below already recorded the outage exactly once, and a
			// tunnel that has never connected is legible without any event at all: dw is published
			// while hb stays 0, which is precisely the "never connected" state the panel reads.
			log.Printf("core/dns: connect: %v", err)
			if d.sleep(backoff) {
				return nil
			}
			backoff = min(backoff*2, dnsBackoffMax)
			continue
		}
		log.Printf("core/dns: session established (%s zone=%s)", d.role(), d.zone)
		d.st.reconnected("dns") // silent on the first connect; pairs a preceding down
		backoff = dnsBackoffMin
		d.conn.Store(&conn)
		d.netToTun(conn) // blocks until the session dies
		d.conn.Store(nil)
		d.clearLive()
		_ = conn.Close()
		if d.isDone() {
			return nil
		}
		d.st.down("session-dead", "dns") // the session ended on its own -> the next connect is a recovery
	}
}

// connect creates a fresh transport and session for one attempt, recording both under the lock so
// Close can tear them down. A fresh transport per attempt gives the server a clean :53 bind and the
// client a fresh resolver socket on every reconnect.
func (d *DNS) connect() (net.Conn, error) {
	codec, err := dnstun.NewCodec(d.zone)
	if err != nil {
		return nil, err
	}
	var t dnstun.WireTransport
	if d.isClient {
		t, err = dnstun.NewDNSClientTransport(d.resolvers, codec)
	} else {
		t, _, err = dnstun.NewDNSServerTransport(d.addr, codec)
	}
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.isClosed() {
		d.mu.Unlock()
		_ = t.Close()
		return nil, net.ErrClosed
	}
	d.curT = t
	d.mu.Unlock()

	var conn net.Conn
	if d.isClient {
		conn, err = dnstun.DialSession(t, d.cfg)
	} else {
		conn, err = dnstun.ServeSession(t, d.cfg) // blocks until a client establishes
	}
	if err != nil {
		// DialSession/ServeSession already closed t on error.
		d.mu.Lock()
		d.curT = nil
		d.mu.Unlock()
		return nil, err
	}
	d.mu.Lock()
	d.curConn = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *DNS) clearLive() {
	d.mu.Lock()
	d.curConn = nil
	d.curT = nil
	d.mu.Unlock()
}

// tunToNet is long-lived: it reads L3 packets and writes them to whatever session is currently live,
// dropping when there is none (the peer retransmits at L4). It ends only when the TUN device closes.
func (d *DNS) tunToNet() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := d.dev.Read(buf)
		if err != nil {
			return // device closed: carrier shutting down
		}
		cp := d.conn.Load()
		if cp == nil {
			continue // no session yet / between sessions — drop
		}
		if err := dnstun.WritePacket(*cp, buf[:n]); err != nil {
			// session down; drop this packet — Run's netToTun will observe the death and reconnect
		}
	}
}

// netToTun pumps one session's inbound packets into the TUN until the session dies.
func (d *DNS) netToTun(conn net.Conn) {
	for {
		pkt, err := dnstun.ReadPacket(conn)
		if err != nil {
			return // session dead -> reconnect
		}
		if _, err := d.dev.Write(pkt); err != nil {
			log.Printf("core/dns: tun write: %v", err)
			return
		}
	}
}

// Close stops the carrier: it signals shutdown and tears down whatever session/transport is live,
// which unblocks netToTun (via the session) and the transport loops.
func (d *DNS) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	d.mu.Lock()
	conn, t := d.curConn, d.curT
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close() // also closes its transport
	} else if t != nil {
		_ = t.Close() // no session yet (e.g. server awaiting a client): stop the transport loops
	}
	return nil
}

func (d *DNS) sleep(dur time.Duration) (closed bool) {
	select {
	case <-d.closeCh:
		return true
	case <-time.After(dur):
		return false
	}
}

func (d *DNS) isDone() bool {
	select {
	case <-d.closeCh:
		return true
	default:
		return false
	}
}

func (d *DNS) isClosed() bool { return d.isDone() }

func (d *DNS) role() string {
	if d.isClient {
		return "client"
	}
	return "server"
}
