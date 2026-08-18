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

func captureSrcLog(sink *srcLogSink) func() {
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	return func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) }
}

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

		if ta.Port != 0 {
			t.Errorf("source %q: bound port %d, want 0 (a source entry's port is not a bind port)", src, ta.Port)
		}
	}
}

func TestDialerNeverDropsASourceInSilence(t *testing.T) {

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
