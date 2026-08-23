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

	dnsMinMTU = dnstun.MinUsefulMTU
)

func zoneBytesToDrop(need int) int { return (need*8 + 4) / 5 }

type DNS struct {
	dev       *tun.Device
	isClient  bool
	cfg       dnstun.SessionConfig
	zone      string
	addr      string
	resolvers []string

	mu      sync.Mutex
	curConn net.Conn
	curT    dnstun.WireTransport
	conn    atomic.Pointer[net.Conn]

	st *coreStatus

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newDNS(dev *tun.Device, isClient bool, addr string, resolvers []string, zone, psk, cipher string) (*DNS, error) {
	codec, err := dnstun.NewCodec(zone)
	if err != nil {
		return nil, err
	}
	mtu := codec.MaxUpstream() - dnstun.SessionOverhead
	if mtu < dnsMinMTU {

		return nil, fmt.Errorf("dns: zone %q leaves only %d bytes per query, and the carrier needs %d "+
			"(KCP spends %d of them on its own header) — shorten the zone by about %d characters",
			zone, mtu, dnsMinMTU, dnstun.KCPOverhead, zoneBytesToDrop(dnsMinMTU-mtu))
	}
	return &DNS{
		dev: dev, isClient: isClient, zone: zone, addr: addr, resolvers: resolvers,
		cfg:     dnstun.SessionConfig{PSK: psk, Cipher: cipher, MTU: mtu},
		closeCh: make(chan struct{}),
	}, nil
}

func DialDNS(dev *tun.Device, resolvers []string, zone, psk, cipher string) (*DNS, error) {
	return newDNS(dev, true, "", resolvers, zone, psk, cipher)
}

func ListenDNS(dev *tun.Device, listenAddr, zone, psk, cipher string) (*DNS, error) {
	return newDNS(dev, false, listenAddr, nil, zone, psk, cipher)
}

func (d *DNS) SetStatusPath(path string) {
	if path == "" {
		return
	}
	d.st = newCoreStatus(path, "dns · "+d.zone)
}

func (d *DNS) Run() error {
	go d.tunToNet()
	backoff := dnsBackoffMin
	for {
		select {
		case <-d.closeCh:
			return nil
		default:
		}
		conn, err := d.connect()
		if err != nil {

			log.Printf("core/dns: connect: %v", err)
			if d.sleep(backoff) {
				return nil
			}
			backoff = min(backoff*2, dnsBackoffMax)
			continue
		}
		log.Printf("core/dns: session established (%s zone=%s)", d.role(), d.zone)
		d.st.reconnected("dns")
		backoff = dnsBackoffMin
		d.conn.Store(&conn)
		d.netToTun(conn)
		d.conn.Store(nil)
		d.clearLive()
		_ = conn.Close()
		if d.isDone() {
			return nil
		}
		d.st.down("session-dead", "dns")
	}
}

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
		conn, err = dnstun.ServeSession(t, d.cfg)
	}
	if err != nil {

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

func (d *DNS) tunToNet() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := d.dev.Read(buf)
		if err != nil {
			return
		}
		cp := d.conn.Load()
		if cp == nil {
			continue
		}
		if err := dnstun.WritePacket(*cp, buf[:n]); err != nil {

		}
	}
}

func (d *DNS) netToTun(conn net.Conn) {
	for {
		pkt, err := dnstun.ReadPacket(conn)
		if err != nil {
			return
		}
		if _, err := d.dev.Write(pkt); err != nil {
			log.Printf("core/dns: tun write: %v", err)
			return
		}
	}
}

func (d *DNS) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	d.mu.Lock()
	conn, t := d.curConn, d.curT
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	} else if t != nil {
		_ = t.Close()
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
