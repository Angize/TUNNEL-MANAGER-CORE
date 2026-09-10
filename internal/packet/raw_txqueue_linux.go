//go:build linux

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

type txQueue struct {
	dev   *tun.Device
	batch *ipv4.PacketConn
	own   *net.IPConn
}

var dropAll = []unix.SockFilter{{Code: 0x06}}

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

func (r *Raw) closeTxQueues() {
	for _, q := range r.txq[1:] {
		if q.own != nil {
			q.own.Close()
		}
	}
}

func (r *Raw) logTxQueues() {
	if len(r.txq) > 1 {
		log.Printf("raw: %d send/receive queues on %s", len(r.txq), r.tunName())
	}
}
