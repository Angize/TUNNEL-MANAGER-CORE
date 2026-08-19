package packet

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/dnstun"
)

func TestDNSRefusesAZoneThatLeavesAnUnusableMTU(t *testing.T) {

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
	for _, n := range []int{10, 20, 40, 75, 87} {
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305"); err == nil {
			shortOK = true
			break
		}
	}
	if !shortOK {
		t.Fatal("no zone up to 87 characters was accepted — those tunnels start and carry traffic today")
	}

	var refused error
	for n := 120; n <= 240; n += 5 {
		if _, err := newDNS(nil, true, "", nil, zoneOf(n), "psk", "chacha20-poly1305"); err != nil {
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

func TestDNSMTUFloorClearsKCPsOwnHeader(t *testing.T) {
	if dnsMinMTU <= dnstun.KCPOverhead {
		t.Fatalf("the MTU floor %d is at or below KCP's own %d-byte header — SetMtu refuses it outright, "+
			"KCP silently keeps its 1400-byte default, and nothing reports it", dnsMinMTU, dnstun.KCPOverhead)
	}

	if dnsMinMTU > 80 {
		t.Fatalf("the MTU floor %d is close to what any zone can leave (~87 for a ten-character zone) — "+
			"almost no dns tunnel could start", dnsMinMTU)
	}

	if dnsMinMTU > 40 {
		t.Fatalf("the MTU floor is %d: that refuses every zone from 75 characters up (mtu 47 and down), "+
			"and those tunnels start, hand SetMtu a value it accepts, and carry traffic. The floor may "+
			"only exclude what KCP itself cannot take", dnsMinMTU)
	}
}

func TestZoneBytesToDropIsHonest(t *testing.T) {
	for _, need := range []int{1, 5, 8, 40, 100} {
		got := zoneBytesToDrop(need)
		if freed := got * 5 / 8; freed < need {
			t.Fatalf("dropping %d characters frees %d bytes, short of the %d needed — the advice sends "+
				"the operator round the same loop twice", got, freed, need)
		}
	}
}
