//go:build linux

package packet

import "syscall"

// SO_SNDBUFFORCE/SO_RCVBUFFORCE set the buffer bypassing net.core.{w,r}mem_max. They need
// CAP_NET_ADMIN — which the core already holds (it opens TUN and raw sockets) — so a large
// buffer applies without an operator first raising the sysctl. The plain SO_*BUF variants
// are the fallback when the privilege is missing (they clamp to the sysctl ceiling).
const (
	soSndbufForce = 32 // SO_SNDBUFFORCE
	soRcvbufForce = 33 // SO_RCVBUFFORCE
)

// applyRawConnBuf runs the setsockopt under the RawConn's Control (so the fd is valid for
// the duration of the call). Used for net.*Conn sockets (udp).
func applyRawConnBuf(rc syscall.RawConn, n int) {
	if rc == nil || n <= 0 {
		return
	}
	_ = rc.Control(func(fd uintptr) { applyFdBuf(int(fd), n) })
}

// applyFdBuf sizes a bare fd's send+receive buffers, preferring the FORCE variants and
// falling back to the clamped ones. Best-effort: a failure just leaves the kernel default,
// so errors are swallowed rather than failing carrier startup. Used for raw/flux fds.
func applyFdBuf(fd, n int) {
	if fd < 0 || n <= 0 {
		return
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soSndbufForce, n) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, n)
	}
	if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvbufForce, n) != nil {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, n)
	}
}
