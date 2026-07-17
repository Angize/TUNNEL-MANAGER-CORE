package dnstun

import (
	"net"
	"sync"
	"time"
)

// Queue bounds. A full queue DROPS the datagram rather than blocking — the correct
// backpressure for a slow, lossy DNS channel, because kcp-go retransmits anything lost.
const (
	sendQueueSize = 1024
	recvQueueSize = 1024
)

type taggedPacket struct {
	p    []byte
	addr net.Addr
}

// QueuePacketConn is a net.PacketConn whose reads/writes are backed by in-memory
// channels instead of a socket, so kcp-go (which speaks net.PacketConn) can run over
// a transport that is not a socket — here, DNS request/response.
//
//   - kcp-go SENDS via WriteTo(p, addr): the datagram is queued; the DNS transport drains
//     it with OutgoingQueue(addr) and ships it inside a DNS message.
//   - the DNS transport RECEIVES a datagram and calls QueueIncoming(p, addr); kcp-go then
//     reads it via ReadFrom.
//
// addr is a logical peer identity (a ClientID on the server, the fixed server addr on the
// client), NOT a UDP address — so a session survives the resolver's source address changing.
// Modeled on the turbo-tunnel pattern (Fifield).
type QueuePacketConn struct {
	local     net.Addr
	recvQueue chan taggedPacket
	mu        sync.Mutex
	sendMap   map[string]chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

// NewQueuePacketConn builds an empty queue-backed PacketConn with local as its LocalAddr.
func NewQueuePacketConn(local net.Addr) *QueuePacketConn {
	return &QueuePacketConn{
		local:     local,
		recvQueue: make(chan taggedPacket, recvQueueSize),
		sendMap:   make(map[string]chan []byte),
		closed:    make(chan struct{}),
	}
}

// sendQueue returns the per-peer outgoing channel for addr, creating it on first use.
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

// OutgoingQueue is the transport's read side of the datagrams kcp-go wants sent to addr.
func (c *QueuePacketConn) OutgoingQueue(addr net.Addr) <-chan []byte { return c.sendQueue(addr) }

// QueueIncoming hands a datagram the transport received (from logical peer addr) to kcp-go.
// It copies p (the caller may reuse its buffer) and drops silently on a full queue or after
// Close, so a stalled reader or a torn-down session never blocks the transport.
func (c *QueuePacketConn) QueueIncoming(p []byte, addr net.Addr) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-c.closed:
	case c.recvQueue <- taggedPacket{buf, addr}:
	default: // full: drop (kcp-go retransmits)
	}
}

// ReadFrom returns the next datagram queued by the transport. It blocks until one arrives
// or the conn closes (then net.ErrClosed, which stops kcp-go's read loop cleanly).
func (c *QueuePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case tp := <-c.recvQueue:
		return copy(p, tp.p), tp.addr, nil
	}
}

// WriteTo queues a datagram kcp-go wants sent to addr. It copies p, never blocks (a full
// per-peer queue drops), and reports the full length so kcp-go treats the send as done.
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
	default: // full: drop (kcp-go retransmits)
	}
	return len(p), nil
}

// Close unblocks any ReadFrom and marks the conn dead. Idempotent.
func (c *QueuePacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// Closed exposes the done channel so a transport loop can stop when the conn closes.
func (c *QueuePacketConn) Closed() <-chan struct{} { return c.closed }

// LocalAddr implements net.PacketConn.
func (c *QueuePacketConn) LocalAddr() net.Addr { return c.local }

// Deadlines are no-ops: kcp-go over an external PacketConn drives its own timers and never
// relies on the underlying conn's deadlines, so a nil (accepting) result is correct here.
func (c *QueuePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *QueuePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *QueuePacketConn) SetWriteDeadline(time.Time) error { return nil }
