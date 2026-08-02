//go:build linux

package packet

import (
	"fmt"
	"log"
	"sync"
	"syscall"
)

// SO_SNDBUFFORCE/SO_RCVBUFFORCE set the buffer bypassing net.core.{w,r}mem_max. They need
// CAP_NET_ADMIN — which the core already holds (it opens TUN and raw sockets) — so a large
// buffer applies without an operator first raising the sysctl. The plain SO_*BUF variants
// are the fallback when the privilege is missing (they clamp to the sysctl ceiling).
const (
	soSndbufForce = 32 // SO_SNDBUFFORCE
	soRcvbufForce = 33 // SO_RCVBUFFORCE
)

// sockBufWarned reports a clamped buffer at most once per DIRECTION per process. Once, not once per
// socket: the cause is a process-wide capability or a host sysctl, so every socket of that direction
// is clamped identically and a line each would be the same sentence repeated.
var sockBufWarned [2]sync.Once

// applyRawConnBuf runs the setsockopt under the RawConn's Control (so the fd is valid for
// the duration of the call). Used for net.*Conn sockets (udp).
func applyRawConnBuf(rc syscall.RawConn, n int) {
	if rc == nil || n <= 0 {
		return
	}
	_ = rc.Control(func(fd uintptr) { applyFdBuf(int(fd), n) })
}

// applyFdBuf sizes a bare fd's send AND receive buffers — for a bidirectional socket. Best-effort:
// a failure leaves the kernel default rather than failing startup, but it no longer does so in
// silence (see sizeBuf).
func applyFdBuf(fd, n int) {
	applyFdSndBuf(fd, n)
	applyFdRcvBuf(fd, n)
}

// applyFdSndBuf sizes only the SEND buffer. Use on a send-only socket (the IP_HDRINCL raw sender):
// it is bound to a real protocol so the kernel also queues matching inbound frames we never read —
// pinning its RCVBUF large would just reserve floodable, undrained kernel memory.
func applyFdSndBuf(fd, n int) {
	sizeBuf(fd, n, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")
}

// applyFdRcvBuf sizes only the RECEIVE buffer. Use on a receive-only socket (the AF_PACKET reader).
func applyFdRcvBuf(fd, n int) {
	sizeBuf(fd, n, soRcvbufForce, syscall.SO_RCVBUF, 1, "receive", "rmem_max")
}

// sizeBuf applies one direction's buffer and REPORTS when the kernel did not give what was asked. When
// the FORCE variant is refused — no CAP_NET_ADMIN, i.e. a container or a hardened unit — the plain option
// is clamped to net.core.{w,r}mem_max, so an operator's 16 MiB silently becomes the host default with
// nothing at any layer saying so. Reading it back costs one getsockopt per socket, once, at startup.
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
		return // we cannot tell what the kernel did, so there is nothing honest to report
	}
	// The kernel stores TWICE what it is given — it budgets its own per-packet bookkeeping in the
	// same number — so the value read back is 2× the usable payload capacity. Comparing the raw
	// read-back against n would call every successful apply a clamp.
	if eff := got / 2; eff < n {
		sockBufWarned[warnIdx].Do(func() {
			log.Printf("core: WARNING sock_buf %d bytes was clamped to %d on the %s buffer%s — raise "+
				"net.core.%s on this host or give the process CAP_NET_ADMIN, or the throughput this "+
				"setting exists to buy never arrives", n, eff, dir, forcedNote(forced), sysctl)
			// ...and to the PANEL, which is the layer the operator actually reads. The log line alone
			// only reaches the core unit's journal, and the node reads that on one branch: after a
			// build that FAILED. A core that started and was merely clamped went through no branch at
			// all, so the setting stayed green in the UI with nothing anywhere saying otherwise.
			noteCfgWarn("sockbuf-clamped", fmt.Sprintf("%s %d %d", dir, n, eff))
		})
	}
}

// forcedNote says which of the two setsockopts was in play, because that is what names the fix: a
// REFUSED force option is a missing capability, while a clamp that survives the force option is the
// sysctl itself.
func forcedNote(forced bool) string {
	if forced {
		return " (the privileged FORCE option was accepted and the kernel still clamped it)"
	}
	return " (the privileged FORCE option was refused, so the plain option was capped by the sysctl)"
}
