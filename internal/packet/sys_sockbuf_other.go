//go:build !linux

package packet

import "syscall"

func applyRawConnBuf(rc syscall.RawConn, n int) {}
func applyFdBuf(fd, n int)                      {}
func applyFdSndBuf(fd, n int)                   {}
func applyFdRcvBuf(fd, n int)                   {}
