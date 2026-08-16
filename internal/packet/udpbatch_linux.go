//go:build linux

package packet

import (
	"net"

	"golang.org/x/net/ipv4"
)

// udpBatch reads a burst off one udp socket in a single recvmmsg. It owns the buffers, so the caller
// must finish with one batch before asking for the next.
type udpBatch struct {
	pc *ipv4.PacketConn
	rb *recvBatcher
	ds []datagram
}

// newUDPBatch wraps a socket. A nil socket gives a nil batcher rather than an error: batching is an
// optimisation, and the caller's single-datagram read is always there.
func newUDPBatch(c *net.UDPConn) *udpBatch {
	if c == nil {
		return nil
	}
	return &udpBatch{
		pc: ipv4.NewPacketConn(c),
		rb: newRecvBatcher(maxRecvBatch),
		ds: make([]datagram, 0, maxRecvBatch),
	}
}

// recv blocks for the first datagram and takes whatever else is already queued behind it.
//
// A message whose address is not a udp one is dropped rather than passed on with a nil address: every
// receive path here keys the peer, the replay window and the reply socket off that address.
func (b *udpBatch) recv() ([]datagram, error) {
	ms, err := b.rb.recv(b.pc)
	if err != nil {
		return nil, err
	}
	b.ds = b.ds[:0]
	for i := range ms {
		ua, ok := ms[i].Addr.(*net.UDPAddr)
		if !ok || ua == nil {
			continue
		}
		b.ds = append(b.ds, datagram{pkt: ms[i].Buffers[0][:ms[i].N], addr: ua})
	}
	return b.ds, nil
}

// udpTx sends a burst of frames in one sendmmsg.
//
// The message array AND its one-element Buffers slices are built once and then only re-pointed at each
// frame. Writing `ipv4.Message{Buffers: [][]byte{pkt}}` per packet allocates that inner slice on the
// hottest path there is.
type udpTx struct {
	pc *ipv4.PacketConn
	ms []ipv4.Message
	n  int
}

func newUDPTx(c *net.UDPConn) *udpTx {
	if c == nil {
		return nil
	}
	t := &udpTx{pc: ipv4.NewPacketConn(c), ms: make([]ipv4.Message, maxBatch)}
	for i := range t.ms {
		t.ms[i].Buffers = make([][]byte, 1)
	}
	return t
}

func (t *udpTx) reset()     { t.n = 0 }
func (t *udpTx) full() bool { return t.n >= maxBatch }
func (t *udpTx) count() int { return t.n }

// add holds one frame for the next flush. pkt must be storage the caller does not reuse before then --
// every framing path here seals into a fresh buffer, so it is.
func (t *udpTx) add(pkt []byte, to *net.UDPAddr) {
	t.ms[t.n].Buffers[0], t.ms[t.n].Addr = pkt, to
	t.n++
}

// flush sends what was added and reports how many left.
//
// A short write is not an error to retry: sendmmsg says how many messages it accepted and the rest are
// dropped here, which is the contract the single-packet path already has with the kernel. Re-sending
// the accepted ones would duplicate packets that already went.
func (t *udpTx) flush(errs *sendErrLog) int {
	sent := sendBatch(t.pc, t.ms[:t.n])
	if sent != t.n {
		errs.note("udp/batch", errShortBatch)
	}
	return sent
}
