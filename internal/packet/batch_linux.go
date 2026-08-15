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

	"golang.org/x/net/ipv4"
)

// maxBatch caps one sendmmsg. The GSO queue is at most 64 KB / MSS segments (~45 at 1400), so this is
// above anything a single read can produce -- it bounds the message array, it is not a target to fill.
const maxBatch = 64

// errShortBatch names the case where the kernel took only part of a burst, so the throttled-send
// log says which path dropped rather than reporting a bare nil.
var errShortBatch = errors.New("sendmmsg accepted only part of the batch")

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
