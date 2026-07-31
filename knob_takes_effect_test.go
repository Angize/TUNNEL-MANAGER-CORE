package main

import (
	"strings"
	"testing"
)

// sniCarrier stands in for a carrier implementing the SetSNISplit seam. applied is what the real
// *TCP returns: false when the transport sends no ClientHello of its own (transport=tcp), true on
// the ws/http/grpc carrier.
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

type deadCarrier struct {
	calls   int
	got     int
	applied bool // what the real carriers return: false on a server that will never read the value
}

func (c *deadCarrier) SetDeadAfter(secs int) bool {
	c.calls, c.got = c.calls+1, secs
	return c.applied
}

// TestSNISplitIsNotClaimedOnACarrierThatDiscardsIt drives the REAL applySNISplit that main calls.
//
// In user terms: a core config with transport=tcp and sni_split=true loads without complaint and
// prints "tnl-core: SNI fragmentation on (mode=…)". No ClientHello is ever split — *TCP.SetSNISplit
// returns at its first condition on a non-ws carrier. The operator reading that log has positive
// confirmation of a defence that is not running.
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
	if !applySNISplit(applies, "ws", "fake", 12, 4) {
		t.Error("applySNISplit reported failure for a carrier that accepted it")
	}
	out = buf.String()
	if !strings.Contains(out, "SNI fragmentation on (mode=fake split_pos=12 ttl=4)") {
		t.Fatalf("a carrier that APPLIES sni_split must still be reported as on, got %q", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("an applied sni_split must not warn: %q", out)
	}
	if applies.gotMode != "fake" || applies.gotPos != 12 || applies.gotTTL != 4 {
		t.Fatalf("the carrier got (%q,%d,%d), want (fake,12,4)", applies.gotMode, applies.gotPos, applies.gotTTL)
	}

	// A carrier without the seam at all (dns, raw, …) must warn rather than say nothing.
	buf.Reset()
	applySNISplit(struct{}{}, "dns", "", 0, 0)
	out = buf.String()
	if !strings.Contains(out, "ignores sni_split") {
		t.Fatalf("a carrier with no SetSNISplit at all must be reported, got %q", out)
	}
}

// TestDeadAfterTakesNoRole drives the REAL applyDeadAfter.
//
// In user terms: the operator sets «مهلتِ خودترمیمی» to 20s and the panel writes it to BOTH ends.
// The client really reaped a silent carrier after 20s; the tcp/ws server — where the same window is
// the connection's read deadline — kept its own ~60s default, because the wiring in main was gated
// on role=="client". Half the tunnel self-healed at the configured speed and half did not.
//
// The signature is the guard: applyDeadAfter takes no role, so the gate cannot come back without
// changing it, and this test fails to compile if it does.
func TestDeadAfterTakesNoRole(t *testing.T) {
	c := &deadCarrier{applied: true}
	buf := captureLog(t)
	if !applyDeadAfter(c, "tcp", 10, 20) {
		t.Error("applyDeadAfter refused a carrier that implements SetDeadAfter")
	}
	out := buf.String()
	if c.calls != 1 || c.got != 20 {
		t.Fatalf("SetDeadAfter called %d times with %d, want 1 with 20", c.calls, c.got)
	}
	if !strings.Contains(out, "self-heal deadline set to 20s") {
		t.Fatalf("the effective deadline was not reported: %q", out)
	}

	// 0 leaves each carrier's own default formula alone, and says nothing.
	c = &deadCarrier{applied: true}
	buf.Reset()
	if applyDeadAfter(c, "tcp", 10, 0) {
		t.Error("dead_after_secs=0 must not be applied")
	}
	out = buf.String()
	if c.calls != 0 || out != "" {
		t.Fatalf("dead_after_secs=0: %d calls, log %q — want neither", c.calls, out)
	}

	// A carrier that cannot take it is reported, not silently skipped (that was the dns bug).
	buf.Reset()
	if applyDeadAfter(struct{}{}, "dns", 10, 20) {
		t.Error("a carrier with no SetDeadAfter must not report success")
	}
	out = buf.String()
	if !strings.Contains(out, "ignores dead_after_secs") {
		t.Fatalf("a carrier with no SetDeadAfter must be reported, got %q", out)
	}
	// A carrier that TAKES the value and will never read it — the server of a connectionless carrier —
	// must not be reported as "set". That line was printed on udp/raw/flux/dns servers, where nothing
	// consults the number, which is the same lie about a knob this function exists to stop telling.
	inert := &deadCarrier{applied: false}
	buf.Reset()
	if applyDeadAfter(inert, "udp", 10, 20) {
		t.Error("a carrier that will not enforce the value must not be reported as having set it")
	}
	out = buf.String()
	if strings.Contains(out, "self-heal deadline set to") {
		t.Fatalf("an inert carrier was reported as enforcing the deadline: %q", out)
	}
	if !strings.Contains(out, "not enforced on this end") {
		t.Fatalf("an inert carrier must say so, got %q", out)
	}
	if inert.got != 20 {
		t.Fatalf("the value must still be handed over (got %d) — only the CLAIM changes", inert.got)
	}
}
