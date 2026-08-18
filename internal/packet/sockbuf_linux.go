//go:build linux

package packet

import (
	"fmt"
	"log"
	"sync"
	"syscall"
)

const (
	soSndbufForce = 32
	soRcvbufForce = 33
)

var sockBufWarned [2]sync.Once

func applyRawConnBuf(rc syscall.RawConn, n int) {
	if rc == nil || n <= 0 {
		return
	}
	_ = rc.Control(func(fd uintptr) { applyFdBuf(int(fd), n) })
}

func applyFdBuf(fd, n int) {
	applyFdSndBuf(fd, n)
	applyFdRcvBuf(fd, n)
}

func applyFdSndBuf(fd, n int) {
	sizeBuf(fd, n, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")
}

func applyFdRcvBuf(fd, n int) {
	sizeBuf(fd, n, soRcvbufForce, syscall.SO_RCVBUF, 1, "receive", "rmem_max")
}

func sizeBuf(fd, n, forceOpt, plainOpt, warnIdx int, dir, sysctl string) {
	if fd < 0 || n <= 0 {
		return
	}
	forced := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, forceOpt, n) == nil
	if !forced {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, plainOpt, n)
	}
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, plainOpt)
	if err != nil {
		return
	}

	if eff := got / 2; eff < n {
		sockBufWarned[warnIdx].Do(func() {
			log.Printf("core: WARNING sock_buf %d bytes was clamped to %d on the %s buffer%s — raise "+
				"net.core.%s on this host or give the process CAP_NET_ADMIN, or the throughput this "+
				"setting exists to buy never arrives", n, eff, dir, forcedNote(forced), sysctl)

			noteCfgWarn("sockbuf-clamped", fmt.Sprintf("%s %d %d", dir, n, eff))
		})
	}
}

func forcedNote(forced bool) string {
	if forced {
		return " (the privileged FORCE option was accepted and the kernel still clamped it)"
	}
	return " (the privileged FORCE option was refused, so the plain option was capped by the sysctl)"
}
