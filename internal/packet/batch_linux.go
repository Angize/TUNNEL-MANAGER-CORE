//go:build linux

package packet

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

const maxBatch = 64

var errShortBatch = errors.New("sendmmsg accepted only part of the batch")

const maxRecvBatch = 64

type recvBatcher struct{ ms []ipv4.Message }

func newRecvBatcher(n int) *recvBatcher {
	ms := make([]ipv4.Message, n)
	for i := range ms {

		ms[i].Buffers = [][]byte{make([]byte, maxDatagram)}
		ms[i].OOB = make([]byte, pktinfoOOBLen)
	}
	return &recvBatcher{ms: ms}
}

func (b *recvBatcher) recv(pc *ipv4.PacketConn) ([]ipv4.Message, error) {
	n, err := pc.ReadBatch(b.ms, syscall.MSG_WAITFORONE)
	if err != nil {
		return nil, err
	}
	return b.ms[:n], nil
}

func batchConn(c *net.IPConn) *ipv4.PacketConn {
	if c == nil {
		return nil
	}
	return ipv4.NewPacketConn(c)
}

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
