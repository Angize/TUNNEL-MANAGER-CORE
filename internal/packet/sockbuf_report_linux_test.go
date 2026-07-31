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

// TestSockBufReportsWhenItWasClamped is the regression test for sock_buf failing in silence.
//
// In user terms: the operator sets sock_buf to 16 MiB in Settings. The panel saves it green, the
// node forwards it, the core accepts it — and if the process is short of CAP_NET_ADMIN (a container,
// a hardened unit) the privileged setsockopt is refused and the plain one is capped by
// net.core.{w,r}mem_max. Both errors were discarded, nothing was read back, and nothing was logged,
// so the operator saw a setting that looked applied everywhere and bought no throughput anywhere.
//
// Driven on a real socket: ask for far more than any sysctl ceiling and require the line.
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

	// MaxInt32: the kernel stores 2× what it is given, so it CANNOT grant this on any host — the
	// doubled value would not fit the int the option is stored in, and it clamps to ~INT_MAX. That
	// makes the clamp unconditional, whether or not this box has CAP_NET_ADMIN or a raised sysctl,
	// which a merely-large request (1 GiB on a root box with SO_SNDBUFFORCE) does not.
	const want = 1<<31 - 1
	sockBufWarned = [2]sync.Once{} // this is process state; start from a known point
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

	// Once per direction per process: a second socket must not repeat the same sentence.
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

// TestSockBufIsSilentWhenItApplied pins the other half: a request the kernel CAN satisfy must say
// nothing at all. A warning on every healthy tunnel would be worse than the silence it replaces.
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

	// 8 KiB is under every default net.core.wmem_max (212992 on stock Linux).
	sockBufWarned = [2]sync.Once{}
	sizeBuf(fd, 8<<10, soSndbufForce, syscall.SO_SNDBUF, 0, "send", "wmem_max")
	if buf.Len() != 0 {
		t.Fatalf("a buffer the kernel granted was reported as clamped: %q", buf.String())
	}
}

// TestCoverProbeHintOnlyOnCover pins the clock-skew hint: a cover carrier whose core handshake
// fails says WHY that can happen, exactly once, and a non-cover carrier says nothing.
//
// The symptom it explains has no other signal: tlscover's server answers a token it cannot open by
// proxying to the real cover site — the same answer it gives a censor's probe, which is what makes
// the carrier probe-resistant — so a clock more than AuthWindowSecs out of step produces a TLS
// session that succeeds against a site which never heard of the core protocol. Nothing can be sent
// back to distinguish it, because anything our client could read, a probe could read too.
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

	// Once per carrier: the dial loop retries forever, and a line per retry is a line per second.
	buf.Reset()
	b.coverProbeHint()
	if buf.Len() != 0 {
		t.Fatalf("the hint repeated on a second failed handshake: %q", buf.String())
	}
}
