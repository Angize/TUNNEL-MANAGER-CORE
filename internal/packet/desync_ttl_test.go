package packet

import (
	"bytes"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestSetDesyncReportsTheCappedTTL(t *testing.T) {
	capture := func(ttl int) string {
		var buf syncBuf
		old := log.Writer()
		flags := log.Flags()
		log.SetOutput(&buf)
		log.SetFlags(0)
		defer func() { log.SetOutput(old); log.SetFlags(flags) }()
		b := &TCP{isClient: true}
		b.SetDesync(true, ttl, 2, "both")
		if !b.dsOn || b.dsTTL != ttl {
			t.Fatalf("SetDesync did not store the config: on=%v ttl=%d", b.dsOn, b.dsTTL)
		}
		return buf.String()
	}

	for _, ttl := range []int{injectMaxTTL + 1, 30, 64, 255} {
		out := capture(ttl)
		if out == "" {
			t.Errorf("fake_ttl=%d exceeds the cap of %d and nothing was logged", ttl, injectMaxTTL)
			continue
		}
		if !strings.Contains(out, strconv.Itoa(ttl)) || !strings.Contains(out, strconv.Itoa(injectMaxTTL)) {
			t.Errorf("fake_ttl=%d: the log names neither the requested nor the effective value: %q", ttl, out)
		}

		if !strings.HasPrefix(out, "core/tcp: ") {
			t.Errorf("fake_ttl=%d: log line does not carry the core/tcp prefix: %q", ttl, out)
		}
	}

	for _, ttl := range []int{1, 4, injectMaxTTL} {
		if out := capture(ttl); out != "" {
			t.Errorf("fake_ttl=%d is within the cap but logged anyway: %q", ttl, out)
		}
	}

	var buf syncBuf
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	(&TCP{isClient: false}).SetDesync(true, 64, 2, "both")
	(&TCP{isClient: true}).SetDesync(false, 64, 2, "both")
	if out := buf.String(); out != "" {
		t.Errorf("a server / a disabled client logged the cap: %q", out)
	}
}
