//go:build linux

// TCP options for an injected decoy segment. A decoy forged on a live connection's 4-tuple has to match
// what that connection's REAL segments look like, and on Linux a data segment carries NOP,NOP,Timestamp
// whenever the handshake negotiated timestamps — a 12-byte option block, data offset 8. A decoy with a
// bare 20-byte header is separable from real traffic on header shape alone, with no flow tracking.
package packet

import (
	"encoding/binary"
	"net"
	"syscall"

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
)

// tcpTimestampOpts returns the TCP option block a decoy on c must carry to match c's real data segments:
// NOP,NOP,Timestamp when the connection negotiated timestamps, nil when it did not or when the socket
// cannot be reached (httpc's synthetic conn, a closed fd). TSecr is random: the peer's last timestamp is
// not readable from the socket, and a flow-tracking DPI already separates the decoy on its forged seq.
func tcpTimestampOpts(c net.Conn) []byte {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	var opts []byte
	_ = raw.Control(func(fd uintptr) {
		ti, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil || ti.Options&tcpiOptTimestamps == 0 {
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
	return opts
}
