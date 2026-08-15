//go:build linux

// One syscall for a burst instead of one per packet.
//
// At the throughput this core reaches, the send path was making a system call for every single packet:
// MEASURED in a netns on a 2-core EPYC, ~500 Mbit/s of 1400-byte packets is ~45,000 sendto per second
// per direction, and the core sat at ~90% of ONE cpu in every configuration tried. sendmmsg carries a
// whole burst across that boundary once.
//
// The burst comes from the TUN's own GSO queue and nowhere else. One kernel read already returns a
// super-packet that readGSO splits into dozens of segments sitting in userspace, so taking them
// together costs nothing and waits for nothing. Nagling packets on a timer to build a bigger batch
// would trade latency for throughput; this trades neither.
package packet

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

// maxBatch caps one sendmmsg. The GSO queue is at most 64 KB / MSS segments (~45 at 1400), so this is
// above anything a single read can produce -- it bounds the message array, it is not a target to fill.
const maxBatch = 64

// errShortBatch names the case where the kernel took only part of a burst, so the throttled-send
// log says which path dropped rather than reporting a bare nil.
var errShortBatch = errors.New("sendmmsg accepted only part of the batch")

// maxRecvBatch caps one recvmmsg. It is a memory trade, not a free cap like the send side's: every
// slot holds its own full-size buffer for as long as the batch is being handled, so 8 buys 7 of every
// 8 receive syscalls back for half a megabyte per tunnel, and 16 would buy only 3 more in 32.
const maxRecvBatch = 8

// recvBatcher owns the message array a batched receive reads into. Each slot keeps its OWN buffer:
// sharing one across slots would leave every message pointing at the same bytes.
type recvBatcher struct{ ms []ipv4.Message }

func newRecvBatcher(n int) *recvBatcher {
	ms := make([]ipv4.Message, n)
	for i := range ms {
		// maxDatagram, the same size the single-packet read used, so nothing that arrives today can be
		// truncated by the change -- a short buffer would fail the AEAD and drop the frame in silence.
		ms[i].Buffers = [][]byte{make([]byte, maxDatagram)}
		ms[i].OOB = make([]byte, pktinfoOOBLen)
	}
	return &recvBatcher{ms: ms}
}

// recv blocks for the FIRST datagram, then takes whatever else is already queued, and returns only the
// filled slots.
//
// MSG_WAITFORONE asks recvmmsg for exactly that rather than for a full array. It is belt and braces,
// not the mechanism: go drives its sockets non-blocking through the netpoller, so the call returns
// what is ready with or without the flag -- which is also why no test can catch its removal.
func (b *recvBatcher) recv(pc *ipv4.PacketConn) ([]ipv4.Message, error) {
	n, err := pc.ReadBatch(b.ms, syscall.MSG_WAITFORONE)
	if err != nil {
		return nil, err
	}
	return b.ms[:n], nil
}

// batchConn wraps a socket so bursts can leave in one call. A nil return is not a failure worth
// reporting: every caller keeps its single-packet path and simply uses it.
func batchConn(c net.PacketConn) *ipv4.PacketConn {
	if c == nil {
		return nil
	}
	return ipv4.NewPacketConn(c)
}

// sendBatch writes every message in one syscall and reports how many left.
//
// A short write is NOT an error: sendmmsg reports how many of the messages it accepted, and the rest
// are simply dropped here. That is the same contract the single-packet path has with the kernel -- a
// datagram carrier drops rather than blocks, and the tunnelled L4 retransmits -- so the caller does not
// need to know, and a partial batch must not turn into a re-send of packets that already went.
func sendBatch(pc *ipv4.PacketConn, ms []ipv4.Message) int {
	if pc == nil || len(ms) == 0 {
		return 0
	}
	n, err := pc.WriteBatch(ms, 0)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
