//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

// liveTCPConn returns a connected loopback *net.TCPConn with data already exchanged, so the socket is
// ESTABLISHED and its TCP_INFO reports the options the handshake actually negotiated.
func liveTCPConn(t *testing.T) *net.TCPConn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- s
		buf := make([]byte, 64)
		if n, err := s.Read(buf); err == nil {
			s.Write(buf[:n])
		}
	}()
	t.Cleanup(func() {
		select {
		case s := <-accepted:
			s.Close()
		default:
		}
	})
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write([]byte("bring the connection to ESTABLISHED")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn)
}

// socketTSVal reads the TSval the kernel would stamp on conn's next segment.
func socketTSVal(t *testing.T, conn *net.TCPConn) (uint32, bool) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var ok bool
	_ = raw.Control(func(fd uintptr) {
		v, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, optTCPTimestamp)
		ok = err == nil
	})
	return uint32(v), ok
}

// TestTCPFakeSegsCarryTheConnectionsOptions drives the REAL decoy builder on a REAL established socket
// and inspects the bytes it would inject. Linux stamps NOP,NOP,Timestamp on every data segment of a
// timestamped connection, so a decoy forged on that same 4-tuple must do the same: a bare 20-byte header
// beside the kernel's 32-byte ones separates decoy from real on header shape alone.
func TestTCPFakeSegsCarryTheConnectionsOptions(t *testing.T) {
	conn := liveTCPConn(t)
	before, ok := socketTSVal(t, conn)
	if !ok {
		t.Skip("this kernel does not expose TCP_TIMESTAMP")
	}

	b := &TCP{dsOn: true, dsTTL: 4, dsCount: 3, dsMode: "ttl"}
	dst, pkts := b.tcpFakeSegs(conn)
	if dst == nil || len(pkts) != 3 {
		t.Fatalf("builder produced %d decoys for dst %v, want 3", len(pkts), dst)
	}
	after, _ := socketTSVal(t, conn)

	for i, ip := range pkts {
		ihl := int(ip[0]&0x0f) * 4
		seg := ip[ihl:]
		off := int(seg[12]>>4) * 4
		if off != 32 {
			t.Fatalf("decoy %d: TCP data offset %d bytes, want 32 — a real segment on this connection "+
				"carries NOP,NOP,Timestamp and this one does not", i, off)
		}
		opts := seg[20:off]
		if opts[0] != tcpOptNOP || opts[1] != tcpOptNOP || opts[2] != tcpOptTimestamp || opts[3] != tcpOptTSLen {
			t.Fatalf("decoy %d: option block % x, want the NOP,NOP,TS(kind 8,len 10) Linux emits", i, opts)
		}
		// The socket's own clock, read either side of the build: a decoy stamped with anything else
		// would sit outside the millisecond window the real segments of this burst carry.
		if tsval := binary.BigEndian.Uint32(opts[4:8]); tsval-before > after-before {
			t.Fatalf("decoy %d: TSval %d is outside the connection's own clock window [%d,%d] — the decoy "+
				"must carry this socket's timestamp, not an invented one", i, tsval, before, after)
		}
		if binary.BigEndian.Uint32(opts[8:12]) == 0 {
			t.Fatalf("decoy %d: TSecr is zero, which no data segment of an established connection sends", i)
		}
		// The checksum has to cover the options too, or the decoy is dropped before any DPI reads it.
		if s := l4Checksum(net.IP(ip[12:16]), net.IP(ip[16:20]), protoTCP, seg); s != 0 {
			t.Fatalf("decoy %d: TCP checksum does not verify (%#04x) over the 32-byte header", i, s)
		}
		if payLen := len(seg) - off; payLen < 48 || payLen > 111 {
			t.Fatalf("decoy %d: payload len %d out of the 48..111 band — options ate into the payload", i, payLen)
		}
	}
}

// TestTCPTimestampOptsWithoutASocket covers the fallback the builder needs when the connection has no
// reachable fd: httpc hands sendTCPFakes a synthetic conn. No options is the correct answer there, since
// nothing can be learned about what the real segments look like.
func TestTCPTimestampOptsWithoutASocket(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if opts := tcpTimestampOpts(c1); opts != nil {
		t.Fatalf("a conn with no syscall.Conn must yield no options, got % x", opts)
	}
}

// TestRawTCPProfileKeepsItsWireFormat is the no-wire-change guard for the shared builder: the raw
// carrier's own protoTCP frames must stay a bare 20-byte header. They are not camouflage beside a kernel
// TCP flow — they ARE the flow — so options there would change the wire for every raw/tcp tunnel.
func TestRawTCPProfileKeepsItsWireFormat(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 1, 2)
	seg := rawEncap("tcp", []byte("payload-bytes"), src, dst, true, 0x1111, 7, 9, 0x2222)
	if off := int(seg[12]>>4) * 4; off != 20 {
		t.Fatalf("raw tcp profile header is %d bytes, want 20 — this is a WIRE CHANGE", off)
	}
	if len(seg) != 20+len("payload-bytes") {
		t.Fatalf("raw tcp segment len %d, want %d", len(seg), 20+len("payload-bytes"))
	}
}

// TestBuildTCPSegRejectsAMalformedOptionBlock pins the safety rule: the data offset must always describe
// the bytes actually behind it. A block that is not a whole number of words, or longer than the field can
// address, is dropped whole rather than stamped into a header that lies about its own length.
func TestBuildTCPSegRejectsAMalformedOptionBlock(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 1, 2)
	for _, tc := range []struct {
		name string
		opts []byte
		want int
	}{
		{"none", nil, 20},
		{"timestamp block", make([]byte, 12), 32},
		{"the 40-byte maximum", make([]byte, 40), 60},
		{"not a whole word", make([]byte, 10), 20},
		{"past what the field can address", make([]byte, 44), 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seg := buildTCPSeg(src, dst, 40000, 443, 1, 2, tcpPshAck, 0xffff, tc.opts, []byte("body"))
			if off := int(seg[12]>>4) * 4; off != tc.want {
				t.Fatalf("data offset %d bytes, want %d", off, tc.want)
			}
			if len(seg) != tc.want+4 {
				t.Fatalf("segment len %d, want %d — the payload must follow the options", len(seg), tc.want+4)
			}
			if string(seg[tc.want:]) != "body" {
				t.Fatalf("payload = %q, want %q", seg[tc.want:], "body")
			}
			if s := l4Checksum(src, dst, protoTCP, seg); s != 0 {
				t.Fatalf("checksum does not verify (%#04x)", s)
			}
		})
	}
}
