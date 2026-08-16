//go:build !linux

package packet

import "net"

// udpBatch does not exist off linux: recvmmsg is a linux call. newUDPBatch returning nil is the
// documented "no batching here" answer, and every caller keeps its single-datagram read.
type udpBatch struct{}

func newUDPBatch(*net.UDPConn) *udpBatch { return nil }

func (b *udpBatch) recv() ([]datagram, error) { return nil, nil }

// udpTx is the send half, absent for the same reason.
type udpTx struct{}

func newUDPTx(*net.UDPConn) *udpTx { return nil }

func (t *udpTx) reset()                       {}
func (t *udpTx) full() bool                   { return true }
func (t *udpTx) count() int                   { return 0 }
func (t *udpTx) add(_ []byte, _ *net.UDPAddr) {}
func (t *udpTx) flush(_ *sendErrLog) int      { return 0 }
