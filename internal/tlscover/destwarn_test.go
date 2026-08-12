package tlscover

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A cover site the server cannot reach makes the cover a LIE: every probe gets a bare close where the real
// site would have answered, which is the one distinguisher this package exists to remove. It used to fail
// with a naked raw.Close() -- no log, no startup warning -- and on an Iran-side server an unreachable
// foreign cover domain is the NORMAL case, so the failure was both common and invisible.
//
// The throttle is the part worth pinning: a censor scanning the port makes the dial fail at probe rate, and
// one line per failure would bury the journal that has to carry it.
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
	// A window later, the next failure speaks again — otherwise a cover that breaks and stays broken is
	// reported once at the beginning of time and never again.
	sv.dialFail.Store(time.Now().Add(-2 * dialFailEvery).UnixNano())
	before := sv.dialFail.Load()
	sv.noteDialFail(net.ErrClosed)
	if sv.dialFail.Load() == before {
		t.Error("after the window elapsed the next failure must emit a line")
	}
}

// NewServer must do NO I/O. The startup probe used to live inside it and read sv.dest from a goroutine while
// the caller was still replacing that field — a real data race the race detector caught on five existing
// tests, because injecting a local dest after construction is exactly how they work. The probe is now the
// caller's explicit call, so this ordering is safe and must stay safe.
func TestNewServerDoesNoIOAndDestMayBeReplacedAfterwards(t *testing.T) {
	sv, err := NewServer("a-sufficiently-long-preshared-key", "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	// The write the old code raced against. Under -race this is the regression guard.
	sv.dest = "127.0.0.1:1"
	if !strings.HasSuffix(sv.dest, ":1") {
		t.Fatal("dest must be replaceable after construction")
	}
	// And the explicit probe must not block the caller, however dead the dest is.
	start := time.Now()
	sv.WarnIfDestUnreachable()
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("WarnIfDestUnreachable blocked the caller for %v; it must probe in the background so a "+
			"slow cover site cannot delay a tunnel coming up", el)
	}
}
