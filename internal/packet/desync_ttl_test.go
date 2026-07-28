package packet

import (
	"bytes"
	"log"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// syncBuf is a concurrency-safe log sink. The global logger is process-wide, so a background
// goroutine left running by another test can write to it while this one reads — a plain
// bytes.Buffer would trip the race detector for reasons that have nothing to do with the fix.
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

// TestSetDesyncReportsTheCappedTTL drives the REAL TCP.SetDesync, not a helper.
//
// specsTCP clamps an inject decoy's TTL to injectMaxTTL because the decoy rides the real
// connection's 4-tuple. That clamp is correct. What was wrong is that nothing said so: config.go
// accepted fake_ttl up to 255, the node stored it, the panel echoed it back in the edit form, and
// main logged "fake-desync on (… ttl=30 …)" — four layers reporting a hop budget the wire never
// carried. This test locks in that the carrier which applies the cap is the one that announces it.
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

	// Above the cap: the operator must be told, and the line must name both numbers so it is
	// actionable rather than a vague warning.
	for _, ttl := range []int{injectMaxTTL + 1, 30, 64, 255} {
		out := capture(ttl)
		if out == "" {
			t.Errorf("fake_ttl=%d exceeds the cap of %d and nothing was logged", ttl, injectMaxTTL)
			continue
		}
		if !strings.Contains(out, strconv.Itoa(ttl)) || !strings.Contains(out, strconv.Itoa(injectMaxTTL)) {
			t.Errorf("fake_ttl=%d: the log names neither the requested nor the effective value: %q", ttl, out)
		}
		// The carrier prefix every other line in tcp.go uses. Worth asserting: writing "core\tcp:"
		// instead of "core/tcp:" is a VALID Go escape, so it compiles, passes a numbers-only check,
		// and ships a line beginning with a tab that no log filter for this carrier will match.
		if !strings.HasPrefix(out, "core/tcp: ") {
			t.Errorf("fake_ttl=%d: log line does not carry the core/tcp prefix: %q", ttl, out)
		}
	}

	// At or below the cap the configured value IS what the wire carries, so there is nothing to
	// report and a line here would be noise on every start.
	for _, ttl := range []int{1, 4, injectMaxTTL} {
		if out := capture(ttl); out != "" {
			t.Errorf("fake_ttl=%d is within the cap but logged anyway: %q", ttl, out)
		}
	}

	// A server, and a client with desync off, must stay silent either way.
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
