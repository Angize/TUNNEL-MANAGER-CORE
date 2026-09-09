package packet

import (
	"sync/atomic"
	"syscall"
)

var sockBufBytes atomic.Int64

func SetSockBuf(n int) { sockBufBytes.Store(int64(n)) }

func wantSockBuf() int { return int(sockBufBytes.Load()) }

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func applyConnSockBuf(c syscallConn) {
	n := wantSockBuf()
	if n <= 0 || c == nil {
		return
	}
	if rc, err := c.SyscallConn(); err == nil {
		applyRawConnBuf(rc, n)
	}
}
