//go:build linux

package packet

import (
	"syscall"
)

func reuseAddr(_, _ string, rc syscall.RawConn) error {
	return rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
}
