//go:build linux

package packet

import (
	"net"
	"syscall"
	"testing"
)

func TestSockBufRoundtrip(t *testing.T) {
	orig := wantSockBuf()
	t.Cleanup(func() { SetSockBuf(orig) })

	SetSockBuf(123456)
	if got := wantSockBuf(); got != 123456 {
		t.Fatalf("wantSockBuf = %d, want 123456", got)
	}

	applyFdBuf(-1, 4<<20)
	SetSockBuf(0)
	applyFdBuf(3, 0)
}

func getBuf(t *testing.T, c syscallConn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v int
	if err := rc.Control(func(fd uintptr) {
		v, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	return v
}

func TestApplyConnSockBufGrows(t *testing.T) {
	orig := wantSockBuf()
	t.Cleanup(func() { SetSockBuf(orig) })

	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer c.Close()

	before := getBuf(t, c, syscall.SO_RCVBUF)
	SetSockBuf(4 << 20)
	applyConnSockBuf(c)
	after := getBuf(t, c, syscall.SO_RCVBUF)

	if after <= before {
		t.Skipf("SO_RCVBUF did not grow (%d -> %d): no CAP_NET_ADMIN and rmem_max at default", before, after)
	}

	if after < 2<<20 {
		t.Fatalf("SO_RCVBUF grew only to %d, expected >= %d", after, 2<<20)
	}
}
