package packet

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
)

// TestDNSRefusesAZoneThatLeavesAnUnusableMTU is the regression test for the dns MTU floor.
//
// In user terms: the panel and the node accept a zone up to 253 characters. Past ~116 the query name
// leaves an MTU under KCP's own 24-byte header, kcp-go's SetMtu refuses it, KCP silently keeps its
// 1400-byte default over a transport that can carry twenty bytes, and the core still comes up and
// logs "session established" — a tunnel that cannot carry anything, with nothing naming the zone.
// That is what this floor exists to refuse, and the refusal has to say what to shorten.
//
// It must NOT refuse more than that. The floor briefly rose to 48 and took the 75..87-character
// zones with it; those start, are accepted by SetMtu, and carry traffic. See the second test.
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
	for _, n := range []int{10, 20, 40, 75, 87} { // measured: these leave 87, 81, 69, 47 and 40 bytes
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305", 0); err == nil {
			shortOK = true
			break
		}
	}
	if !shortOK {
		t.Fatal("no zone up to 87 characters was accepted — those tunnels start and carry traffic today")
	}

	// A zone long enough to squeeze the per-query budget must be refused, and the error must say
	// what the operator can actually change.
	var refused error
	for n := 120; n <= 240; n += 5 { // an 88-character zone leaves 39 and is where the floor bites
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305", 0); err != nil {
			refused = err
			break
		}
	}
	if refused == nil {
		t.Fatalf("no zone between 120 and 240 characters was refused — a zone that leaves under %d bytes "+
			"per query cannot carry traffic, and starting anyway is what hid the cause", dnstun.MinUsefulMTU)
	}
	msg := refused.Error()
	for _, want := range []string{"per query", "shorten the zone"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must tell the operator what to change; %q is missing from %q", want, msg)
		}
	}
}

// TestDNSMTUFloorClearsKCPsOwnHeader pins the floor from BOTH sides, which is the part this file got
// wrong the first time. It has to be above what kcp-go's SetMtu refuses (or the carrier dies
// silently) and no higher, because every extra byte of floor bans a zone length that works today.
func TestDNSMTUFloorClearsKCPsOwnHeader(t *testing.T) {
	if dnsMinMTU <= dnstun.KCPOverhead {
		t.Fatalf("the MTU floor %d is at or below KCP's own %d-byte header — SetMtu refuses it outright, "+
			"KCP silently keeps its 1400-byte default, and nothing reports it", dnsMinMTU, dnstun.KCPOverhead)
	}
	// The ceiling. A DNS query name is 255 bytes and base32 costs 8 characters per 5, so even a
	// ten-character zone leaves only ~87 (measured). A floor near that refuses zones that work.
	if dnsMinMTU > 80 {
		t.Fatalf("the MTU floor %d is close to what any zone can leave (~87 for a ten-character zone) — "+
			"almost no dns tunnel could start", dnsMinMTU)
	}
	// ⚠ THE REAL GUARD, and the one this file got wrong before. The floor exists to keep SetMtu from
	// refusing, NOT to express an opinion about throughput. A "half the query is header" rule sounds
	// principled and costs the 75..87-character zones, which do start and do carry traffic. Refusing
	// a slow tunnel is not this constant's call; the operator picked the zone.
	//
	// Zone length -> MTU, measured on the box: 40->69, 74->48, 75->47, 80->44, 87->40, 88->39.
	// Anything at or under 40 must therefore stay ACCEPTED, or a working delegation stops booting.
	if dnsMinMTU > 40 {
		t.Fatalf("the MTU floor is %d: that refuses every zone from 75 characters up (mtu 47 and down), "+
			"and those tunnels start, hand SetMtu a value it accepts, and carry traffic. The floor may "+
			"only exclude what KCP itself cannot take", dnsMinMTU)
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
