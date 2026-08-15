//go:build linux

// One send pipeline per TUN queue, so the send path stops being a single goroutine.
//
// This is the other half of the receive-side writers, and neither half works alone: opening a queue
// makes the kernel steer packets onto it in BOTH directions, so a queue with a writer but no reader
// swallows everything the kernel puts there -- including the handshake, which is how the tunnel fails
// to come up at all rather than merely running slow.
//
// Each pipeline needs its OWN socket as well as its own queue. Go takes a write lock per socket, so
// senders that share one make no more progress than a single sender: MEASURED, four goroutines on one
// socket moved 0.29 Mpps and on four sockets 0.98 Mpps -- same work, same kernel, different fds.
package packet

import (
	"fmt"
	"log"
	"net"
	"strconv"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// txQueue is one send pipeline: a TUN queue to read from and a socket to send on.
type txQueue struct {
	dev   *tun.Device
	batch *ipv4.PacketConn
	own   *net.IPConn // the socket this queue opened; nil for queue 0, whose socket is the carrier's
}

// dropAll accepts zero bytes of every packet, which the kernel treats as discard. A raw socket is
// handed every packet of its protocol whether or not anyone reads it, so without this each extra SEND
// socket would take its own full copy of the inbound stream into a buffer nobody drains.
var dropAll = []unix.SockFilter{{Code: 0x06}} // BPF_RET|BPF_K with k = 0

// txSocket opens one more raw socket on proto, for sending only.
func txSocket(proto int) (*net.IPConn, error) {
	c, err := net.ListenIP("ip4:"+strconv.Itoa(proto), &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	rc, err := c.SyscallConn()
	if err != nil {
		c.Close()
		return nil, err
	}
	var serr error
	prog := &unix.SockFprog{Len: uint16(len(dropAll)), Filter: &dropAll[0]}
	if cerr := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	}); cerr != nil || serr != nil {
		c.Close()
		return nil, fmt.Errorf("muting the extra send socket: %w", firstErr(cerr, serr))
	}
	applyConnSockBuf(c)
	return c, nil
}

func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// buildTxQueues pairs each extra TUN queue with a socket of its own. Queue 0 is the carrier's existing
// device and socket, so it needs nothing new.
//
// A queue that cannot get a socket is a hard failure, not something to run without: the kernel is
// already steering flows onto every queue the interface has, so one without a reader is a blackhole.
func (r *Raw) buildTxQueues(extra []*tun.Device, proto int) error {
	r.txq = []txQueue{{dev: r.dev, batch: r.batch}}
	for i, d := range extra {
		c, err := txSocket(proto)
		if err != nil {
			r.closeTxQueues()
			return fmt.Errorf("send queue %d: %w", i+1, err)
		}
		r.txq = append(r.txq, txQueue{dev: d, batch: batchConn(c), own: c})
	}
	return nil
}

// closeTxQueues shuts the sockets the extra queues opened. The TUN queues belong to whoever opened
// them; queue 0's socket is the carrier's own and closes with it.
func (r *Raw) closeTxQueues() {
	for _, q := range r.txq[1:] {
		if q.own != nil {
			q.own.Close()
		}
	}
}

// logTxQueues says how many pipelines a tunnel actually got, because "workers" is an operator knob
// and a silently-ignored one is worse than none.
func (r *Raw) logTxQueues() {
	if len(r.txq) > 1 {
		log.Printf("raw: %d send/receive queues on %s", len(r.txq), r.tunName())
	}
}
