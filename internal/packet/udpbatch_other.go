//go:build !linux

package packet

import "net"

// udpBatch does not exist off linux: recvmmsg is a linux call. newUDPBatch returning nil is the
// documented "no batching here" answer, and every caller keeps its single-datagram read.
type udpBatch struct{}

func newUDPBatch(*net.UDPConn) *udpBatch { return nil }

func (b *udpBatch) recv() ([]datagram, error) { return nil, nil }
