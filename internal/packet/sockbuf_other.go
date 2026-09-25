//go:build !linux

package packet

import "syscall"

func applyRawConnBuf(rc syscall.RawConn, n int, knob string) {}
func applyFdBuf(fd, n int, knob string)                      {}
func applyFdSndBuf(fd, n int, knob string)                   {}
func applyFdRcvBuf(fd, n int, knob string)                   {}
