//go:build !linux

package packet

import "syscall"

func reuseAddr(_, _ string, _ syscall.RawConn) error { return nil }
