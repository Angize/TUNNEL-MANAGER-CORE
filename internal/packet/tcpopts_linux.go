//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tcpiOptTimestamps = 0x01

	optTCPTimestamp = 24

	tcpOptNOP       = 1
	tcpOptTimestamp = 8
	tcpOptTSLen     = 10

	decoyWindow = 0xffff
)

const (
	tiOffOptions     = unsafe.Offsetof(unix.TCPInfo{}.Options)
	tiOffWScale      = tiOffOptions + 1
	tiOffRcvSsthresh = unsafe.Offsetof(unix.TCPInfo{}.Rcv_ssthresh)
	tiOffRcvWnd      = unsafe.Offsetof(unix.TCPInfo{}.Rcv_wnd)
)

func tcpDecoyShape(c net.Conn) (opts []byte, window uint16) {
	window = decoyWindow
	sc, ok := c.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		var buf [512]byte
		info := tcpInfo(fd, buf[:])
		if uintptr(len(info)) <= tiOffWScale {
			return
		}

		wscale := info[tiOffWScale] >> 4
		if w, ok := tcpInfoU32(info, tiOffRcvWnd); ok {
			window = scaleWindow(w, wscale)
		} else if w, ok := tcpInfoU32(info, tiOffRcvSsthresh); ok {

			window = scaleWindow(w, wscale)
		}
		if info[tiOffOptions]&tcpiOptTimestamps == 0 {
			return
		}
		tsval, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPTimestamp)
		if err != nil {
			return
		}
		opts = []byte{tcpOptNOP, tcpOptNOP, tcpOptTimestamp, tcpOptTSLen, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(opts[4:8], uint32(tsval))
		binary.BigEndian.PutUint32(opts[8:12], randSeq32())
	})
	return
}

func tcpInfo(fd uintptr, buf []byte) []byte {
	n := uint32(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.IPPROTO_TCP),
		uintptr(syscall.TCP_INFO), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if e != 0 || int(n) > len(buf) {
		return nil
	}
	return buf[:n]
}

func tcpInfoU32(info []byte, off uintptr) (uint32, bool) {
	if uintptr(len(info)) < off+4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(info[off : off+4])
	return v, v > 0
}

func scaleWindow(bytes uint32, wscale byte) uint16 {
	if w := bytes >> wscale; w <= 0xffff {
		return uint16(w)
	}
	return 0xffff
}
