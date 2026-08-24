package packet

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func TestRawPortReachesBothTheWireAndTheAntiLeakRule(t *testing.T) {
	const custom = 51820

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

	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", custom, 0, isClient, false, false)
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

	for _, bad := range []int{0, -1, 65536, 1 << 20} {
		if got := rawPortOr(bad); got != 0 {
			t.Errorf("rawPortOr(%d) = %d, want 0 so rawPorts falls back to the default", bad, got)
		}
	}
	if s, d := rawPorts(true, 0, 0); s != rawClientPort || d != rawServerPort {
		t.Errorf("an unset port must keep the default pair, got %d->%d", s, d)
	}

	for p := range rawProfiles {
		want := p == "udp" || p == "tcp"
		if got := RawProfileHasPorts(p); got != want {
			t.Errorf("RawProfileHasPorts(%q) = %v, want %v", p, got, want)
		}
	}
}
