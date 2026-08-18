package tlscover

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestCoverDialFailureIsReportedButThrottled(t *testing.T) {
	sv, err := NewServer("a-sufficiently-long-preshared-key", "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for i := 0; i < 500; i++ {
		before := sv.dialFail.Load()
		sv.noteDialFail(net.ErrClosed)
		if sv.dialFail.Load() != before {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("500 failures in the same window emitted %d lines, want exactly 1 — the journal that has "+
			"to carry this cannot absorb one line per probe", lines)
	}
	if got := sv.dialN.Load(); got != 499 {
		t.Errorf("the suppressed failures must still be COUNTED so the one line can say how many: got %d, want 499", got)
	}

	sv.dialFail.Store(time.Now().Add(-2 * dialFailEvery).UnixNano())
	before := sv.dialFail.Load()
	sv.noteDialFail(net.ErrClosed)
	if sv.dialFail.Load() == before {
		t.Error("after the window elapsed the next failure must emit a line")
	}
}

func TestNewServerDoesNoIOAndDestMayBeReplacedAfterwards(t *testing.T) {
	sv, err := NewServer("a-sufficiently-long-preshared-key", "example.invalid")
	if err != nil {
		t.Fatal(err)
	}

	sv.dest = "127.0.0.1:1"
	if !strings.HasSuffix(sv.dest, ":1") {
		t.Fatal("dest must be replaceable after construction")
	}

	start := time.Now()
	sv.WarnIfDestUnreachable()
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("WarnIfDestUnreachable blocked the caller for %v; it must probe in the background so a "+
			"slow cover site cannot delay a tunnel coming up", el)
	}
}
