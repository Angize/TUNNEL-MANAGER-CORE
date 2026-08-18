//go:build linux

package packet

import (
	"encoding/binary"
	"log"
	"net"

	"golang.org/x/sys/unix"
)

const bpfAcceptAll = 0x40000

func bpfIPProto(proto int) []unix.SockFilter {
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(proto), Jt: 0, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: bpfAcceptAll},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}

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

func bpfDropAll() []unix.SockFilter {
	return []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
}

func attachFilter(fd int, prog []unix.SockFilter, what string) {
	if len(prog) == 0 {
		return
	}
	fp := &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fp); err != nil {
		log.Printf("%s: socket filter not attached (%v) — every host packet will be copied to userspace and dropped there", what, err)
	}
}
