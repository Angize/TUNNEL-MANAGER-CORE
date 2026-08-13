//go:build linux

package packet

import (
	"encoding/binary"
	"log"
	"net"

	"golang.org/x/sys/unix"
)

// An AF_PACKET socket is handed a copy of EVERY IPv4 frame the host sees, and both carriers that use
// one then throw nearly all of it away in Go. On a busy box that is a copy into userspace, a scheduler
// wake-up and a bounds check per packet of somebody else's traffic. A socket filter is the same
// decision made in the kernel, before the copy.
//
// Classic BPF, because that is what SO_ATTACH_FILTER takes. SOCK_DGRAM strips the link header, so
// offset 0 is the start of the IPv4 header: byte 9 is the protocol and bytes 16..19 the destination.

// bpfAcceptAll is the return value that keeps a whole frame (any length above the MTU will do).
const bpfAcceptAll = 0x40000

// bpfIPProto keeps only IPv4 frames of one protocol number.
func bpfIPProto(proto int) []unix.SockFilter {
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(proto), Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: bpfAcceptAll},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}

// bpfIPProtoDst keeps only IPv4 frames of one protocol number addressed to one destination — the decoy
// server's whole receive criterion, which is otherwise applied per packet in Go.
func bpfIPProtoDst(proto int, dst net.IP) []unix.SockFilter {
	v4 := dst.To4()
	if v4 == nil {
		return bpfIPProto(proto)
	}
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(proto), Jt: 0, Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: binary.BigEndian.Uint32(v4), Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: bpfAcceptAll},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}

// bpfDropAll keeps nothing, for a socket opened only to find out whether it CAN be opened.
func bpfDropAll() []unix.SockFilter {
	return []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
}

// attachFilter installs prog on fd. Best-effort and logged rather than fatal: the receive loops all
// re-check what the filter selects, so a kernel that refuses it costs throughput, not correctness.
// Frames queued between socket() and here are not filtered, which is the same reason those Go-side
// checks stay.
func attachFilter(fd int, prog []unix.SockFilter, what string) {
	if len(prog) == 0 {
		return
	}
	fp := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fp); err != nil {
		log.Printf("%s: socket filter not attached (%v) — every host packet will be copied to userspace and dropped there", what, err)
	}
}
