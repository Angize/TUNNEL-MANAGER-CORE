package main

import (
	"strings"
	"testing"
)

type sniCarrier struct {
	applied bool
	calls   int
	gotMode string
	gotPos  int
	gotTTL  int
}

func (c *sniCarrier) SetSNISplit(on bool, pos int, mode string, ttl int) bool {
	c.calls, c.gotMode, c.gotPos, c.gotTTL = c.calls+1, mode, pos, ttl
	return c.applied
}

func TestSNISplitIsNotClaimedOnACarrierThatDiscardsIt(t *testing.T) {
	discards := &sniCarrier{applied: false}
	buf := captureLog(t)
	if applySNISplit(discards, "tcp", "split", 0, 0) {
		t.Error("applySNISplit reported success for a carrier that discarded it")
	}
	out := buf.String()
	if discards.calls != 1 {
		t.Fatalf("the carrier was asked %d times, want exactly 1", discards.calls)
	}
	if strings.Contains(out, "SNI fragmentation on") {
		t.Fatalf("a carrier that DISCARDS sni_split was reported as having it on: %q", out)
	}
	if !strings.Contains(out, "ignores sni_split") {
		t.Fatalf("a discarded sni_split must be reported, got %q", out)
	}

	applies := &sniCarrier{applied: true}
	buf.Reset()
	if !applySNISplit(applies, "ws", "disorder", 12, 4) {
		t.Error("applySNISplit reported failure for a carrier that accepted it")
	}
	out = buf.String()
	if !strings.Contains(out, "SNI fragmentation on (mode=disorder split_pos=12 ttl=4)") {
		t.Fatalf("a carrier that APPLIES sni_split must still be reported as on, got %q", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("an applied sni_split must not warn: %q", out)
	}
	if applies.gotMode != "disorder" || applies.gotPos != 12 || applies.gotTTL != 4 {
		t.Fatalf("the carrier got (%q,%d,%d), want (disorder,12,4)", applies.gotMode, applies.gotPos, applies.gotTTL)
	}

	for _, mode := range []string{"fake", "split"} {
		c := &sniCarrier{applied: true}
		buf.Reset()
		applySNISplit(c, "ws", mode, 12, 4)
		out = buf.String()
		if strings.Contains(out, "ttl=4") {
			t.Fatalf("mode=%s reported ttl=4, but only disorder reads split_ttl: %q", mode, out)
		}
		if !strings.Contains(out, "SNI fragmentation on (mode="+mode+" split_pos=12") {
			t.Fatalf("mode=%s must still be reported as on, got %q", mode, out)
		}
	}

	buf.Reset()
	applySNISplit(struct{}{}, "dns", "", 0, 0)
	out = buf.String()
	if !strings.Contains(out, "ignores sni_split") {
		t.Fatalf("a carrier with no SetSNISplit at all must be reported, got %q", out)
	}
}
