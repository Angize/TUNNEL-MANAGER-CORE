//go:build !linux

package packet

import (
	"syscall"
	"time"
)

func applyRawConnBuf(rc syscall.RawConn, n int, knob string) {}
func applyUserTimeout(rc syscall.RawConn, d time.Duration)   {}
func applyFdBuf(fd, n int, knob string)                      {}
func applyFdSndBuf(fd, n int, knob string)                   {}
func applyFdRcvBuf(fd, n int, knob string)                   {}
