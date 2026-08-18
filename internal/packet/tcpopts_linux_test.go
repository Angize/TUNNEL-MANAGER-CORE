//go:build linux

package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func liveTCPConn(t *testing.T) *net.TCPConn { return liveTCPConnRcvBuf(t, 0) }

func liveTCPConnRcvBuf(t *testing.T, rcvbuf int) *net.TCPConn {
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
	d := &net.Dialer{}
	if rcvbuf > 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvbuf)
			})
		}
	}
	c, err := d.Dial("tcp", ln.Addr().String())
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

func socketWindow(t *testing.T, conn *net.TCPConn) (uint16, bool) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var win uint16
	var ok bool
	_ = raw.Control(func(fd uintptr) {
		var buf [512]byte
		info := tcpInfo(fd, buf[:])
		if uintptr(len(info)) <= tiOffWScale {
			return
		}
		w, got := tcpInfoU32(info, tiOffRcvWnd)
		if !got {
			if w, got = tcpInfoU32(info, tiOffRcvSsthresh); !got {
				return
			}
		}
		win, ok = scaleWindow(w, info[tiOffWScale]>>4), true
	})
	return win, ok
}

func TestTCPFakeSegsCarryTheConnectionsOptions(t *testing.T) {
	conn := liveTCPConn(t)
	before, ok := socketTSVal(t, conn)
	if !ok {
		t.Skip("this kernel does not expose TCP_TIMESTAMP")
	}
	wantWin, haveWin := socketWindow(t, conn)

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
		if win := binary.BigEndian.Uint16(seg[14:16]); !haveWin {
			t.Fatalf("decoy %d: this kernel reports no receive window at all, which liveTCPConn should not produce", i)
		} else if win != wantWin {
			t.Fatalf("decoy %d: window %d, want this connection's own %d — a decoy that always advertises "+
				"the maximum is separable from real traffic on the window field alone", i, win, wantWin)
		} else if win == 0xffff {
			t.Fatalf("decoy %d: window is the 0xffff maximum, so this test cannot tell the fix from the bug", i)
		}

		if tsval := binary.BigEndian.Uint32(opts[4:8]); tsval-before > after-before {
			t.Fatalf("decoy %d: TSval %d is outside the connection's own clock window [%d,%d] — the decoy "+
				"must carry this socket's timestamp, not an invented one", i, tsval, before, after)
		}
		if binary.BigEndian.Uint32(opts[8:12]) == 0 {
			t.Fatalf("decoy %d: TSecr is zero, which no data segment of an established connection sends", i)
		}

		if s := l4Checksum(net.IP(ip[12:16]), net.IP(ip[16:20]), protoTCP, seg); s != 0 {
			t.Fatalf("decoy %d: TCP checksum does not verify (%#04x) over the 32-byte header", i, s)
		}
		if payLen := len(seg) - off; payLen < 48 || payLen > 111 {
			t.Fatalf("decoy %d: payload len %d out of the 48..111 band — options ate into the payload", i, payLen)
		}
	}
}

func TestTCPDecoyShapeWithoutASocket(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	opts, window := tcpDecoyShape(c1)
	if opts != nil {
		t.Fatalf("a conn with no syscall.Conn must yield no options, got % x", opts)
	}
	if window != decoyWindow {
		t.Fatalf("window %d, want the %d fallback", window, decoyWindow)
	}
}

func TestTCPDecoyShapeIsPerConnection(t *testing.T) {
	if _, ok := socketWindow(t, liveTCPConn(t)); !ok {
		t.Skip("this kernel reports no receive window")
	}
	_, big := tcpDecoyShape(liveTCPConn(t))
	_, small := tcpDecoyShape(liveTCPConnRcvBuf(t, 8192))

	if big == decoyWindow || small == decoyWindow {
		t.Fatalf("windows (%d, %d) fell back to the 0xffff constant on a live socket", big, small)
	}
	if big == small {
		t.Fatalf("a default receive buffer and an 8 KiB one both advertised %d — the window is being "+
			"substituted, not read from the connection", big)
	}
}

func TestRawTCPProfileCarriesLiveFlowShape(t *testing.T) {
	src, dst := net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 1, 2)
	const tsval, tsecr = 0x01020304, 0x0a0b0c0d
	seg := rawEncap("tcp", []byte("payload-bytes"), src, dst, true, 0x1111, 0, 0, 7, 9, 0x2222, tsval, tsecr, tcpPshAck)

	if off := int(seg[12]>>4) * 4; off != 32 {
		t.Fatalf("raw tcp header is %d bytes, want 32 (20 + NOP,NOP,Timestamp)", off)
	}
	if len(seg) != 32+len("payload-bytes") {
		t.Fatalf("raw tcp segment len %d, want %d", len(seg), 32+len("payload-bytes"))
	}
	wantOpt := []byte{tcpOptNOPKind, tcpOptNOPKind, tcpOptTSKind, tcpOptTSBytes,
		0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d}
	if got := seg[20:32]; !bytes.Equal(got, wantOpt) {
		t.Fatalf("tcp options = % x, want % x", got, wantOpt)
	}
	if pts := peerTSVal(seg); pts != tsval {
		t.Fatalf("peerTSVal read %#x, want %#x", pts, tsval)
	}
	if seg[13] != tcpPshAck {
		t.Fatalf("data segment flags = %#x, want PSH|ACK %#x", seg[13], tcpPshAck)
	}
}

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
