//go:build linux

package packet

import (
	"encoding/binary"
	"log"
	"sort"

	"golang.org/x/sys/unix"
)

const maxFilterSrcs = 255

func srcFilter(set map[string]struct{}, portOff uint32, port uint16) []unix.SockFilter {
	keys := make([]string, 0, len(set))
	for k := range set {
		if len(k) == 4 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 || len(keys) > maxFilterSrcs {
		return nil
	}
	sort.Strings(keys)
	n := len(keys)
	f := make([]unix.SockFilter, 0, n+7)
	f = append(f, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 12})
	for i, k := range keys {
		f = append(f, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: uint8(n - i), K: binary.BigEndian.Uint32([]byte(k))})
	}
	f = append(f, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K})
	if port != 0 {
		f = append(f,
			unix.SockFilter{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH},
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: portOff},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: uint32(port)},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K})
	}
	return append(f, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0x40000})
}

func (r *Raw) portMatch() (uint32, uint16) {
	if !RawProfileHasPorts(r.profile) || r.portsMove() {
		return 0, 0
	}
	if r.isClient {
		return 0, r.port
	}
	return 2, r.port
}

func (r *Raw) filterSrc(set map[string]struct{}) {
	off, port := r.portMatch()
	prog := srcFilter(set, off, port)
	if prog == nil || r.conn == nil {
		return
	}
	rc, err := r.conn.SyscallConn()
	if err == nil {
		var serr error
		err = rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
				&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]})
		})
		if err == nil {
			err = serr
		}
	}
	if err != nil {
		log.Printf("raw: the kernel source filter was not installed (%v) — foreign packets are read and dropped in user space instead", err)
	}
}
