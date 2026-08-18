package dnstun

import (
	"net"
	"sync"
	"time"
)

const (
	sendQueueSize = 1024
	recvQueueSize = 1024
)

type taggedPacket struct {
	p    []byte
	addr net.Addr
}

type QueuePacketConn struct {
	local     net.Addr
	recvQueue chan taggedPacket
	mu        sync.Mutex
	sendMap   map[string]chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func NewQueuePacketConn(local net.Addr) *QueuePacketConn {
	return &QueuePacketConn{
		local:     local,
		recvQueue: make(chan taggedPacket, recvQueueSize),
		sendMap:   make(map[string]chan []byte),
		closed:    make(chan struct{}),
	}
}

func (c *QueuePacketConn) sendQueue(addr net.Addr) chan []byte {
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	q := c.sendMap[key]
	if q == nil {
		q = make(chan []byte, sendQueueSize)
		c.sendMap[key] = q
	}
	return q
}

func (c *QueuePacketConn) OutgoingQueue(addr net.Addr) <-chan []byte { return c.sendQueue(addr) }

func (c *QueuePacketConn) QueueIncoming(p []byte, addr net.Addr) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-c.closed:
	case c.recvQueue <- taggedPacket{buf, addr}:
	default:
	}
}

func (c *QueuePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case tp := <-c.recvQueue:
		return copy(p, tp.p), tp.addr, nil
	}
}

func (c *QueuePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.sendQueue(addr) <- buf:
	default:
	}
	return len(p), nil
}

func (c *QueuePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *QueuePacketConn) Closed() <-chan struct{} { return c.closed }

func (c *QueuePacketConn) LocalAddr() net.Addr { return c.local }

func (c *QueuePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *QueuePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *QueuePacketConn) SetWriteDeadline(time.Time) error { return nil }
