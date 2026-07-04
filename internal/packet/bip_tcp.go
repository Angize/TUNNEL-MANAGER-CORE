// This file implements the "bip" carrier over TCP. It mirrors bip.go (same
// magic/type frame and Sealer contract) but adapts to a byte stream:
//
// Wire format (length-prefixed so the reader can reframe the stream):
//
//	[0:2] uint16 big-endian N = length of the frame that follows (magic+type+payload)
//	[2]   magic = 0xB1
//	[3]   type  = 0 data | 1 ping | 2 pong
//	[4:]  payload (sealed(nonce||ct) for data when crypto is on)
//
// Roles: the "server" listens and accepts connections; the "client" dials and
// reconnects automatically with a short backoff. Because a bip tunnel is a
// single point-to-point link, only one connection is active at a time — a new
// accepted connection replaces (and closes) the previous one. A single TUN
// reader feeds whichever connection is currently live via an atomic pointer,
// so no L3 packet is bound to a connection that may have dropped.
package packet

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-ENGINE/internal/tun"
)

const maxFrame = 65535 // uint16 length prefix ceiling (payload fits far under this)

// connFramer wraps a stream connection with a write lock so the TUN reader and
// the keepalive loop can both emit frames without interleaving bytes.
type connFramer struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *connFramer) writeFrame(typ byte, payload []byte) error {
	n := 2 + len(payload) // magic + type + payload
	if n > maxFrame {
		return io.ErrShortWrite
	}
	frame := make([]byte, 2+n)
	binary.BigEndian.PutUint16(frame[0:2], uint16(n))
	frame[2] = magic
	frame[3] = typ
	copy(frame[4:], payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.conn.Write(frame)
	return err
}

// BipTCP carries L3 packets between a TUN device and a TCP peer.
type BipTCP struct {
	dev       *tun.Device
	sealer    Sealer
	keepalive time.Duration

	isClient bool
	addr     string // server: listen addr; client: peer addr

	ln      net.Listener
	cur     atomic.Pointer[connFramer] // currently live connection (nil when none)
	closed  atomic.Bool
	closeCh chan struct{}
}

// DialTCP (client role) targets peerAddr and reconnects on drop.
func DialTCP(peerAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration) (*BipTCP, error) {
	return &BipTCP{dev: dev, sealer: sealer, keepalive: keepalive, isClient: true, addr: peerAddr, closeCh: make(chan struct{})}, nil
}

// ListenTCP (server role) binds listenAddr and accepts connections.
func ListenTCP(listenAddr string, dev *tun.Device, sealer Sealer, keepalive time.Duration) (*BipTCP, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &BipTCP{dev: dev, sealer: sealer, keepalive: keepalive, addr: listenAddr, ln: ln, closeCh: make(chan struct{})}, nil
}

// Run blocks until Close is called. The TUN reader runs for the whole lifetime;
// the connection side either accepts (server) or dials-with-retry (client).
func (b *BipTCP) Run() error {
	go b.tunLoop()
	if b.isClient {
		go b.keepaliveLoop()
		b.dialLoop()
	} else {
		b.acceptLoop()
	}
	return nil
}

// Close stops the carrier and unblocks Run.
func (b *BipTCP) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	close(b.closeCh)
	if b.ln != nil {
		b.ln.Close()
	}
	if c := b.cur.Load(); c != nil {
		c.conn.Close()
	}
	return nil
}

// acceptLoop (server) takes each new connection as the live one, closing any
// predecessor so a stale half-open link cannot keep receiving TUN traffic.
func (b *BipTCP) acceptLoop() {
	for {
		conn, err := b.ln.Accept()
		if err != nil {
			if b.closed.Load() {
				return
			}
			log.Printf("bip/tcp: accept error: %v", err)
			continue
		}
		log.Printf("bip/tcp: peer connected from %s", conn.RemoteAddr())
		cf := &connFramer{conn: conn}
		if old := b.cur.Swap(cf); old != nil {
			old.conn.Close()
		}
		go b.serve(cf)
	}
}

// dialLoop (client) keeps a connection to the server alive, retrying on drop.
func (b *BipTCP) dialLoop() {
	for {
		if b.closed.Load() {
			return
		}
		conn, err := net.DialTimeout("tcp", b.addr, 10*time.Second)
		if err != nil {
			log.Printf("bip/tcp: dial %s failed: %v", b.addr, err)
			if b.sleep(1 * time.Second) {
				return
			}
			continue
		}
		log.Printf("bip/tcp: connected to %s", b.addr)
		cf := &connFramer{conn: conn}
		b.cur.Store(cf)
		// prime the server with a ping so it has a frame to react to
		_ = cf.writeFrame(typePing, nil)
		b.serve(cf) // blocks until this connection dies
		b.cur.CompareAndSwap(cf, nil)
		if b.sleep(1 * time.Second) {
			return
		}
	}
}

// serve reads framed messages from one connection until it errors or closes.
func (b *BipTCP) serve(cf *connFramer) {
	r := bufio.NewReaderSize(cf.conn, maxFrame+2)
	var hdr [2]byte
	buf := make([]byte, maxFrame)
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			b.onConnErr(cf, err)
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < 2 {
			b.onConnErr(cf, io.ErrUnexpectedEOF)
			return
		}
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			b.onConnErr(cf, err)
			return
		}
		if buf[0] != magic {
			continue // desync guard; skip this frame
		}
		switch buf[1] {
		case typePing:
			_ = cf.writeFrame(typePong, nil)
		case typePong:
			// keepalive ack
		case typeData:
			payload := buf[2:n]
			if b.sealer != nil {
				opened, err := b.sealer.Open(payload)
				if err != nil {
					log.Printf("bip/tcp: open error (auth fail?): %v", err)
					continue
				}
				payload = opened
			}
			if _, err := b.dev.Write(payload); err != nil {
				log.Printf("bip/tcp: tun write error: %v", err)
			}
		}
	}
}

func (b *BipTCP) onConnErr(cf *connFramer, err error) {
	cf.conn.Close()
	b.cur.CompareAndSwap(cf, nil)
	if !b.closed.Load() {
		log.Printf("bip/tcp: connection closed: %v", err)
	}
}

// tunLoop reads L3 packets from TUN and writes them to whichever connection is
// currently live, sealing first when crypto is on. Packets that arrive while no
// connection is up are dropped (the peer will retransmit at the L4 layer).
func (b *BipTCP) tunLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, err := b.dev.Read(buf)
		if err != nil {
			if !b.closed.Load() {
				log.Printf("bip/tcp: tun read error: %v", err)
			}
			return
		}
		cf := b.cur.Load()
		if cf == nil {
			continue // no live peer connection yet
		}
		payload := buf[:n]
		if b.sealer != nil {
			sealed, err := b.sealer.Seal(payload)
			if err != nil {
				log.Printf("bip/tcp: seal error: %v", err)
				continue
			}
			payload = sealed
		}
		if err := cf.writeFrame(typeData, payload); err != nil {
			b.onConnErr(cf, err)
		}
	}
}

// keepaliveLoop (client) pings the server over the live connection so idle
// tunnels do not get reaped by stateful middleboxes.
func (b *BipTCP) keepaliveLoop() {
	t := time.NewTicker(b.keepalive)
	defer t.Stop()
	for {
		select {
		case <-b.closeCh:
			return
		case <-t.C:
			if cf := b.cur.Load(); cf != nil {
				if err := cf.writeFrame(typePing, nil); err != nil {
					b.onConnErr(cf, err)
				}
			}
		}
	}
}

// sleep waits d or returns true if Close fired during the wait.
func (b *BipTCP) sleep(d time.Duration) bool {
	select {
	case <-b.closeCh:
		return true
	case <-time.After(d):
		return false
	}
}
