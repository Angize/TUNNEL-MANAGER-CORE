//go:build !linux

package packet

import "net"

type udpBatch struct{}

func newUDPBatch(*net.UDPConn) *udpBatch { return nil }

func (b *udpBatch) recv() ([]datagram, error) { return nil, nil }

type udpTx struct{}

func newUDPTx(*net.UDPConn) *udpTx { return nil }

func (t *udpTx) reset()                       {}
func (t *udpTx) full() bool                   { return true }
func (t *udpTx) count() int                   { return 0 }
func (t *udpTx) add(_ []byte, _ *net.UDPAddr) {}
func (t *udpTx) flush(_ *sendErrLog) int      { return 0 }
