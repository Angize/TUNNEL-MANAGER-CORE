//go:build linux

package packet

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDesyncWireEmission(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root (raw sockets / CAP_NET_RAW)")
	}
	const proto = protoBare
	const ttl = 7
	const count = 3

	rfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		t.Skipf("cannot open raw receive socket: %v", err)
	}
	defer syscall.Close(rfd)
	if err := syscall.Bind(rfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind receiver: %v", err)
	}
	tv := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	lo := net.IPv4(127, 0, 0, 1)
	r := &Raw{isClient: true, proto: proto, fakeFd: -1}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: lo})
	r.SetDesync(true, ttl, count, "ttl")
	if !r.desync.on || r.fakeFd < 0 {
		t.Skip("SetDesync could not open the fake socket here")
	}
	defer func() {
		r.sendMu.Lock()
		r.sendDown = true
		r.sendMu.Unlock()
		syscall.Close(r.fakeFd)
	}()

	r.sendFakes(&net.IPAddr{IP: lo})

	buf := make([]byte, 1500)
	seen := 0
	deadline := time.Now().Add(2 * time.Second)
	for seen < count && time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(rfd, buf, 0)
		if err != nil {
			break
		}
		if n < 20 || buf[9] != byte(proto) {
			continue
		}
		if buf[8] != ttl {
			t.Fatalf("decoy TTL = %d, want the stamped %d", buf[8], ttl)
		}
		ihl := int(buf[0]&0x0f) * 4
		if payLen := n - ihl; payLen < 48 || payLen > 111 {
			t.Fatalf("decoy payload len %d out of the 48..111 band", payLen)
		}
		seen++
	}
	if seen != count {
		t.Fatalf("received %d decoys on the wire, want %d", seen, count)
	}
}
