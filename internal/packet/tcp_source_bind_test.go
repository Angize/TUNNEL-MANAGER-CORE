package packet

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// srcLogSink is a concurrency-safe log sink. The global logger is process-wide, so a goroutine left
// running by another test can write to it while this one reads — a plain bytes.Buffer would trip the
// race detector for reasons unrelated to what is being tested.
type srcLogSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *srcLogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *srcLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureSrcLog redirects the standard logger into sink and returns the restore func.
func captureSrcLog(sink *srcLogSink) func() {
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	return func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) }
}

// TestDialerAcceptsSourceWithPort drives the REAL TCP.dialer — the function that decides what the next
// connect() binds to — not a helper beside it. config.go promises an accidental "ip:port" in a source
// pool is tolerated, and udp and raw/flux strip the port; tcp did not, and with the bind AND the warning
// both inside `if ip != nil` the entry was discarded in silence. 127.0.0.1, so the bind is attempted.
func TestDialerAcceptsSourceWithPort(t *testing.T) {
	for _, src := range []string{"127.0.0.1", "127.0.0.1:0", "127.0.0.1:8080"} {
		b := &TCP{isClient: true, bindIP: src}
		d := b.dialer(time.Second)
		if d.LocalAddr == nil {
			t.Errorf("source %q: no LocalAddr — the configured source was silently dropped", src)
			continue
		}
		ta, ok := d.LocalAddr.(*net.TCPAddr)
		if !ok {
			t.Errorf("source %q: LocalAddr is %T, want *net.TCPAddr", src, d.LocalAddr)
			continue
		}
		if !ta.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("source %q: bound %v, want 127.0.0.1", src, ta.IP)
		}
		// The port in a source entry is incidental — binding it would pin one ephemeral port across
		// every re-dial and collide on the second. The other three carriers drop it too.
		if ta.Port != 0 {
			t.Errorf("source %q: bound port %d, want 0 (a source entry's port is not a bind port)", src, ta.Port)
		}
	}
}

// TestDialerNeverDropsASourceInSilence closes the class instead of the one string: whatever the
// source turns out to be, the dialer either binds it or says why it did not. Silence was the real
// defect — a value that parsed to nothing took the same path as no value at all.
func TestDialerNeverDropsASourceInSilence(t *testing.T) {
	// Strings that cannot yield an IP by any route, so the outcome does not depend on which
	// addresses happen to be configured on the machine running the test.
	for _, src := range []string{"not-an-ip", "1.2.3.4.5", "::gg"} {
		var sink srcLogSink
		restore := captureSrcLog(&sink)
		d := (&TCP{isClient: true, bindIP: src}).dialer(time.Second)
		restore()
		if d.LocalAddr != nil {
			t.Errorf("source %q: bound %v, but it is not a usable address", src, d.LocalAddr)
		}
		out := sink.String()
		if out == "" {
			t.Errorf("source %q: dropped with no output at all", src)
			continue
		}
		if !strings.HasPrefix(out, "core/tcp: ") {
			t.Errorf("source %q: log line does not carry the core/tcp prefix: %q", src, out)
		}
	}
	// An empty source is not a configured one — it means "kernel default" — so it must stay quiet.
	var sink srcLogSink
	restore := captureSrcLog(&sink)
	d := (&TCP{isClient: true}).dialer(time.Second)
	restore()
	if d.LocalAddr != nil {
		t.Errorf("an unset source bound %v", d.LocalAddr)
	}
	if out := sink.String(); out != "" {
		t.Errorf("an unset source logged: %q", out)
	}
}
