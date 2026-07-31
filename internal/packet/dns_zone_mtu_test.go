package packet

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
)

// TestDNSRefusesAZoneThatLeavesAnUnusableMTU is the regression test for the dns MTU floor.
//
// In user terms: the panel and the node accept a zone up to 253 characters. Past a certain length
// the query name has almost no room left for tunnel data — and the old floor of 40 accepted that,
// because kcp-go only refuses an MTU at or below its own 24-byte header. So the core came up, logged
// "session established", and then spent most of every DNS query on the KCP header while a single
// ordinary packet shattered into dozens of queries. The tunnel was not slow, it could not carry
// anything, and nothing anywhere named the zone as the cause.
func TestDNSRefusesAZoneThatLeavesAnUnusableMTU(t *testing.T) {
	// Build zones by length and find where the carrier draws the line.
	zoneOf := func(n int) string {
		var sb strings.Builder
		for sb.Len() < n {
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for i := 0; i < 40 && sb.Len() < n; i++ {
				sb.WriteByte('t')
			}
		}
		return sb.String()
	}

	shortOK := false
	for _, n := range []int{10, 20, 40} { // measured on the box: these leave 87, 81 and 69 bytes
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305", 0); err == nil {
			shortOK = true
			break
		}
	}
	if !shortOK {
		t.Fatal("no short zone was accepted at all — the floor rejects configurations that work")
	}

	// A zone long enough to squeeze the per-query budget must be refused, and the error must say
	// what the operator can actually change.
	var refused error
	for n := 80; n <= 200; n += 5 { // 80 characters already leaves only 44 bytes (measured)
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305", 0); err != nil {
			refused = err
			break
		}
	}
	if refused == nil {
		t.Fatalf("no zone between 80 and 200 characters was refused — a zone that leaves under %d bytes "+
			"per query cannot carry traffic, and starting anyway is what hid the cause", dnstun.MinUsefulMTU)
	}
	msg := refused.Error()
	for _, want := range []string{"per query", "shorten the zone"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must tell the operator what to change; %q is missing from %q", want, msg)
		}
	}
}

// TestDNSMTUFloorClearsKCPsOwnHeader pins the property behind the number, not the number: the floor
// has to leave the payload bigger than the header KCP spends on every segment. The old 40 did not —
// it left 16 payload bytes against a 24-byte header — and kcp-go accepted it, which is exactly why
// nothing complained.
func TestDNSMTUFloorClearsKCPsOwnHeader(t *testing.T) {
	if dnsMinMTU <= dnstun.KCPOverhead {
		t.Fatalf("the MTU floor %d is at or below KCP's own %d-byte header — every segment would be "+
			"pure overhead", dnsMinMTU, dnstun.KCPOverhead)
	}
	if payload := dnsMinMTU - dnstun.KCPOverhead; payload < dnstun.KCPOverhead {
		t.Fatalf("the MTU floor %d leaves %d payload bytes against a %d-byte header — more than half of "+
			"every DNS query would be KCP header", dnsMinMTU, payload, dnstun.KCPOverhead)
	}
	// And the other direction, which is the mistake this test caught the first time: a DNS query name
	// is 255 bytes and base32 costs 8 characters per 5, so even a ten-character zone leaves only ~87.
	// A floor above that ceiling refuses EVERY zone and the carrier becomes unusable.
	if dnsMinMTU > 80 {
		t.Fatalf("the MTU floor %d is above what any zone can leave (~87 for a ten-character zone) — "+
			"no dns tunnel could ever start", dnsMinMTU)
	}
}

// TestZoneBytesToDropIsHonest pins the advice in the error message. base32 costs 8 characters per 5
// raw bytes, so one zone character buys back five eighths of a byte; the number quoted has to be at
// least enough, or the operator shortens the zone, tries again, and gets the same error.
func TestZoneBytesToDropIsHonest(t *testing.T) {
	for _, need := range []int{1, 5, 8, 40, 100} {
		got := zoneBytesToDrop(need)
		if freed := got * 5 / 8; freed < need {
			t.Fatalf("dropping %d characters frees %d bytes, short of the %d needed — the advice sends "+
				"the operator round the same loop twice", got, freed, need)
		}
	}
}
