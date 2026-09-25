package packet

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
)

var sockBufBytes, tcpBufBytes atomic.Int64

func SetSockBuf(n int) { sockBufBytes.Store(int64(n)) }

func wantSockBuf() int { return int(sockBufBytes.Load()) }

func SetTCPBuf(n int) { tcpBufBytes.Store(int64(n)) }

func wantTCPBuf() int { return int(tcpBufBytes.Load()) }

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func applyConnSockBuf(c syscallConn) {
	n := wantSockBuf()
	if n <= 0 || c == nil {
		return
	}
	if rc, err := c.SyscallConn(); err == nil {
		applyRawConnBuf(rc, n, "sock_buf")
	}
}

func tcpBufControl(_, _ string, rc syscall.RawConn) error {
	applyRawConnBuf(rc, wantTCPBuf(), "tcp_buf")
	return nil
}

func dialControl(network, address string, rc syscall.RawConn) error {
	if err := reuseAddr(network, address, rc); err != nil {
		return err
	}
	return tcpBufControl(network, address, rc)
}

func listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: tcpBufControl}
	return lc.Listen(context.Background(), "tcp", addr)
}
