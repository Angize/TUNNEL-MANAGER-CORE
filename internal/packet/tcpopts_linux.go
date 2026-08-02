//go:build linux

// Header shape for an injected decoy segment. A decoy forged on a live connection's 4-tuple has to match
// what that connection's REAL segments look like, or it is separable on header shape alone with no flow
// tracking: Linux stamps NOP,NOP,Timestamp on every data segment of a timestamped connection, and the
// window field carries the receive window it is currently advertising, never a constant.
package packet

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// tcpiOptTimestamps is TCPI_OPT_TIMESTAMPS in struct tcp_info's tcpi_options byte: the handshake
	// negotiated RFC 7323 timestamps, so every data segment of this connection carries the option.
	tcpiOptTimestamps = 0x01

	// optTCPTimestamp is TCP_TIMESTAMP. getsockopt returns the TSval the kernel would stamp on this
	// connection's next segment — its millisecond clock plus the connection's own random offset, which
	// is why the value cannot be guessed from outside.
	optTCPTimestamp = 24

	tcpOptNOP       = 1
	tcpOptTimestamp = 8
	tcpOptTSLen     = 10

	// decoyWindow is what a decoy advertises when the connection's own window cannot be read. The
	// maximum is a poor choice — a real segment's window moves with the receive buffer — but nothing
	// better is knowable then.
	decoyWindow = 0xffff
)

// Offsets into struct tcp_info. Taken from the x/sys layout rather than written out, so they follow the
// struct instead of drifting from it. tiOffWScale has no Go field to name: the kernel packs
// tcpi_snd_wscale:4 and tcpi_rcv_wscale:4 into one byte, which Go turns into padding.
const (
	tiOffOptions     = unsafe.Offsetof(unix.TCPInfo{}.Options)
	tiOffWScale      = tiOffOptions + 1
	tiOffRcvSsthresh = unsafe.Offsetof(unix.TCPInfo{}.Rcv_ssthresh)
	tiOffRcvWnd      = unsafe.Offsetof(unix.TCPInfo{}.Rcv_wnd)
)

// tcpDecoyShape returns the header fields a decoy on c must copy from c's real data segments: the TCP
// option block and the advertised window. A connection that negotiated no timestamps gets no options,
// which is what ITS real segments look like. Falls back to no options and decoyWindow when the socket
// cannot be reached (httpc's synthetic conn, a closed fd). TSecr is random: the peer's last timestamp is
// not readable from the socket, and a flow-tracking DPI already separates the decoy on its forged seq.
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
		// The RECEIVE scale — the shift the peer applies to the window WE advertise — is the HIGH
		// nibble, which is what a capture with an asymmetric SO_RCVBUF says.
		wscale := info[tiOffWScale] >> 4
		if w, ok := tcpInfoU32(info, tiOffRcvWnd); ok {
			window = scaleWindow(w, wscale)
		} else if w, ok := tcpInfoU32(info, tiOffRcvSsthresh); ok {
			// tcpi_rcv_wnd is recent. Older kernels stop short of it, and the window clamp is the
			// closest thing they do report: it tracks the advertised window on an idle connection,
			// which is exactly when decoys go out.
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

// tcpInfo reads struct tcp_info into buf and returns the prefix this kernel actually filled. The raw
// getsockopt rather than unix.GetsockoptTCPInfo, for two reasons: the window scales live in a bitfield
// byte Go cannot name, and only the returned LENGTH tells a tail field this kernel does not have apart
// from one it reports as zero.
func tcpInfo(fd uintptr, buf []byte) []byte {
	n := uint32(len(buf))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(syscall.IPPROTO_TCP),
		uintptr(syscall.TCP_INFO), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if e != 0 || int(n) > len(buf) {
		return nil
	}
	return buf[:n]
}

// tcpInfoU32 reads one 32-bit tcp_info field, reporting false when this kernel's struct stops short of it
// or the field is zero (an unset tail field and a genuine zero window are not worth telling apart: both
// mean there is no window here to copy).
func tcpInfoU32(info []byte, off uintptr) (uint32, bool) {
	if uintptr(len(info)) < off+4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(info[off : off+4])
	return v, v > 0
}

// scaleWindow turns an advertised receive window in BYTES into the 16-bit field a segment carries: the
// peer multiplies it back by the scale negotiated in the handshake.
func scaleWindow(bytes uint32, wscale byte) uint16 {
	if w := bytes >> wscale; w <= 0xffff {
		return uint16(w)
	}
	return 0xffff
}
