//go:build linux

package packet

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestSockBufReportsWhenItWasClamped(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	defer syscall.Close(fd)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	const want = 1<<31 - 1
	sockBufWarned = [2]sync.Once{}
	sizeBuf(fd, want, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")

	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got/2 >= want {
		t.Fatalf("the kernel claims it granted %d of %d — the request was chosen so that it cannot", got/2, want)
	}
	out := buf.String()
	if !strings.Contains(out, "sock_buf") || !strings.Contains(out, "clamped") {
		t.Fatalf("the kernel gave %d of the %d requested and nothing was logged: %q — the operator has "+
			"no way to learn the setting did not take", got/2, want, out)
	}
	if !strings.Contains(out, "wmem_max") {
		t.Fatalf("the report must name the sysctl that caps it, got %q", out)
	}

	buf.Reset()
	fd2, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	defer syscall.Close(fd2)
	sizeBuf(fd2, want, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")
	if buf.Len() != 0 {
		t.Fatalf("reported twice for one process-wide cause: %q", buf.String())
	}
}

func TestSockBufIsSilentWhenItApplied(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	defer syscall.Close(fd)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	sockBufWarned = [2]sync.Once{}
	sizeBuf(fd, 8<<10, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")
	if buf.Len() != 0 {
		t.Fatalf("a buffer the kernel granted was reported as clamped: %q", buf.String())
	}
}

func TestCoverProbeHintOnlyOnCover(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	plain := &TCP{}
	plain.coverProbeHint()
	if buf.Len() != 0 {
		t.Fatalf("a carrier without cover explained a cover-only failure: %q", buf.String())
	}

	b := &TCP{cover: true, coverSNI: "www.example.com"}
	b.coverProbeHint()
	out := buf.String()
	if !strings.Contains(out, "www.example.com") || !strings.Contains(out, "clock skew") {
		t.Fatalf("the hint must name the cover host and the clock, got %q", out)
	}
	if !strings.Contains(out, "PSK mismatch") {
		t.Fatalf("the hint must name the OTHER cause too, or it sends the operator down one path: %q", out)
	}

	buf.Reset()
	b.coverProbeHint()
	if buf.Len() != 0 {
		t.Fatalf("the hint repeated on a second failed handshake: %q", buf.String())
	}
}
