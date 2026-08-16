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
