package packet

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// TestRawPortReachesBothTheWireAndTheAntiLeakRule.
//
// The udp profile's forged header said :443 — QUIC's port — so a path that drops UDP/443 wholesale
// dropped the entire carrier, and the only "plausible" shape it had was the filtered one. raw_port
// moves that number. What makes it a knob and not a decoration is that it has to land in TWO places at
// once: the bytes on the wire, and the OUTPUT rule that stops our own kernel answering those packets
// with an ICMP port-unreachable. Set one and forget the other and the tunnel leaks a reply per packet
// to the peer, which is worse than the port it was trying to escape.
func TestRawPortReachesBothTheWireAndTheAntiLeakRule(t *testing.T) {
	const custom = 51820 // WireGuard's port: an ordinary thing to see, unlike QUIC on a filtered path

	for _, profile := range []string{"udp", "tcp"} {
		for _, isClient := range []bool{true, false} {
			pkt := rawEncap(profile, []byte("payload"), testSrc, testDst, isClient, 0xBEEF, custom, 0, 7, 9, 0x11223344, 0, 0, tcpPshAck)
			sport := binary.BigEndian.Uint16(pkt[0:2])
			dport := binary.BigEndian.Uint16(pkt[2:4])
			wantS, wantD := rawPorts(isClient, custom, 0)
			if sport != wantS || dport != wantD {
				t.Errorf("raw/%s isClient=%v: wire ports %d->%d, want %d->%d",
					profile, isClient, sport, dport, wantS, wantD)
			}
			if sport != custom && dport != custom {
				t.Errorf("raw/%s isClient=%v: neither port is the configured %d (%d->%d) — the knob did not reach the wire",
					profile, isClient, custom, sport, dport)
			}
			if sport == rawServerPort || dport == rawServerPort {
				t.Errorf("raw/%s isClient=%v: the default %d is still on the wire (%d->%d)",
					profile, isClient, rawServerPort, sport, dport)
			}
		}
	}

	// The tcp anti-leak rule matches OUR kernel's RST, whose ports are the pair we send on. It must be
	// built from the same number, or the rule stops matching the moment the port is changed.
	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", custom, isClient, false, false)
		if len(got) != 1 {
			t.Fatalf("tcp isClient=%v: want exactly one anti-leak rule, got %v", isClient, got)
		}
		rule := strings.Join(got[0], " ")
		if !strings.Contains(rule, strconv.Itoa(custom)) {
			t.Errorf("tcp isClient=%v: the anti-leak rule does not carry the configured port %d: %s",
				isClient, custom, rule)
		}
		if strings.Contains(rule, strconv.Itoa(rawServerPort)) {
			t.Errorf("tcp isClient=%v: the anti-leak rule still matches the default %d: %s",
				isClient, rawServerPort, rule)
		}
	}

	// 0 and out-of-range mean "unset": the profile default, not a zero port on the wire.
	for _, bad := range []int{0, -1, 65536, 1 << 20} {
		if got := rawPortOr(bad); got != 0 {
			t.Errorf("rawPortOr(%d) = %d, want 0 so rawPorts falls back to the default", bad, got)
		}
	}
	if s, d := rawPorts(true, 0, 0); s != rawClientPort || d != rawServerPort {
		t.Errorf("an unset port must keep the default pair, got %d->%d", s, d)
	}

	// A profile that forges no ports has nothing to override, and config validation leans on this.
	for p := range rawProfiles {
		want := p == "udp" || p == "tcp"
		if got := RawProfileHasPorts(p); got != want {
			t.Errorf("RawProfileHasPorts(%q) = %v, want %v", p, got, want)
		}
	}
}
