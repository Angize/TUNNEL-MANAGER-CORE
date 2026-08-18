//go:build linux

package packet

import (
	"bufio"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func tcpWinProbes(t *testing.T) int {
	t.Helper()
	f, err := os.Open("/proc/net/netstat")
	if err != nil {
		t.Skipf("no /proc/net/netstat: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var hdr []string
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != "TcpExt:" {
			continue
		}
		if hdr == nil {
			hdr = fields
			continue
		}
		for i, name := range hdr {
			if name == "TCPWinProbe" && i < len(fields) {
				n, cerr := strconv.Atoi(fields[i])
				if cerr != nil {
					t.Skipf("TCPWinProbe not a number: %q", fields[i])
				}
				return n
			}
		}
		t.Skip("this kernel does not report TCPWinProbe")
	}
	t.Skip("no TcpExt section in /proc/net/netstat")
	return 0
}

func TestLeavingRepairModeSendsNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 256)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						c.Close()
						return
					}
				}
			}(c)
		}
	}()

	const passes = 5
	conns := make([]net.Conn, 0, passes)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < passes; i++ {
		c, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Fatalf("dial: %v", derr)
		}
		conns = append(conns, c)
	}
	time.Sleep(200 * time.Millisecond)

	before := tcpWinProbes(t)
	for _, c := range conns {
		sc, ok := c.(syscall.Conn)
		if !ok {
			t.Fatal("a *net.TCPConn must expose a raw fd")
		}
		raw, rerr := sc.SyscallConn()
		if rerr != nil {
			t.Fatalf("SyscallConn: %v", rerr)
		}
		if _, _, ok := readSeqs(raw); !ok {
			t.Skip("TCP_REPAIR is unavailable here (needs CAP_NET_ADMIN) — nothing to measure")
		}
	}
	time.Sleep(200 * time.Millisecond)
	after := tcpWinProbes(t)

	if delta := after - before; delta > 1 {
		t.Errorf("reading the sequence numbers of %d idle sockets emitted %d TCP window probes: leaving repair mode with 0 transmits a bare ACK, so every sni_mode=fake connection carries one between the handshake and the ClientHello",
			passes, delta)
	}
}
