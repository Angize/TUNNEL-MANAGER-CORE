//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
)

// The forged client source port used to be the constant 51820 and nothing else. An operator who picks a
// different one has to get it in three places at once, or the tunnel is worse than before it was offered:
// the wire, the path the status file publishes, and the anti-leak DROP rule. The rule is the one that bites
// silently — it is built from the ports, so a rule written for 51820 while the wire carries 4500 stops
// matching, and the kernel's RST reaches the peer on every close.
func TestAFixedSourcePortReachesTheWireThePathAndTheAntiLeakRule(t *testing.T) {
	const custom = 4500
	if custom == rawClientPort {
		t.Fatal("pick a port that is NOT the default, or this test proves nothing")
	}

	for _, profile := range []string{"udp", "tcp"} {
		for _, isClient := range []bool{true, false} {
			r := &Raw{profile: profile, isClient: isClient, port: rawServerPort}
			r.setSportMode(false, custom)

			if got := r.cport(); got != custom {
				t.Errorf("raw/%s isClient=%v: cport()=%d, want the configured %d",
					profile, isClient, got, custom)
			}
			if r.sportFix != custom {
				t.Errorf("raw/%s isClient=%v: sportFix=%d, want %d — the anti-leak rule reads this one",
					profile, isClient, r.sportFix, custom)
			}

			// the wire
			pkt := rawEncap(profile, []byte("payload"), testSrc, testDst, isClient,
				0xBEEF, rawServerPort, custom, 7, 9, 0x11223344, 0, 0, tcpPshAck)
			sport := binary.BigEndian.Uint16(pkt[0:2])
			dport := binary.BigEndian.Uint16(pkt[2:4])
			wantS, wantD := rawPorts(isClient, rawServerPort, custom)
			if sport != wantS || dport != wantD {
				t.Errorf("raw/%s isClient=%v: wire %d->%d, want %d->%d",
					profile, isClient, sport, dport, wantS, wantD)
			}
			if sport != custom && dport != custom {
				t.Errorf("raw/%s isClient=%v: neither wire port is the configured %d (%d->%d)",
					profile, isClient, custom, sport, dport)
			}
			if sport == rawClientPort || dport == rawClientPort {
				t.Errorf("raw/%s isClient=%v: the default client port %d is still on the wire (%d->%d)",
					profile, isClient, rawClientPort, sport, dport)
			}

			// the path the status file publishes
			r.localIP.Store(&net.IPAddr{IP: testSrc})
			r.peer.Store(&net.IPAddr{IP: testDst})
			k, _ := r.livePath()
			ws, wd := rawPorts(isClient, rawServerPort, custom)
			if k.Sport != ws || k.Dport != wd {
				t.Errorf("raw/%s isClient=%v: livePath %d->%d, want %d->%d",
					profile, isClient, k.Sport, k.Dport, ws, wd)
			}
		}
	}

	// the anti-leak rule
	for _, isClient := range []bool{true, false} {
		got := rawDropMatches(testDst, "tcp", rawServerPort, custom, isClient, false, false)
		if len(got) != 1 {
			t.Fatalf("isClient=%v: %d rules, want exactly 1", isClient, len(got))
		}
		rule := strings.Join(got[0], " ")
		if !strings.Contains(rule, strconv.Itoa(custom)) {
			t.Errorf("isClient=%v: the rule does not carry the configured source port %d: %s",
				isClient, custom, rule)
		}
		if strings.Contains(rule, strconv.Itoa(rawClientPort)) {
			t.Errorf("isClient=%v: the rule still matches the default client port %d, so it no longer "+
				"describes the packet the kernel would send: %s", isClient, rawClientPort, rule)
		}
	}
}

// The number must not survive where it cannot be honoured: a profile that forges no L4 header at all, or a
// tunnel whose source port rolls. In both cases sportFix has to stay 0 so every reader falls back to what
// the wire really does.
func TestAFixedSourcePortIsDroppedWhereItCannotHold(t *testing.T) {
	for _, profile := range []string{"bare", "icmp", "gre", "esp", "ipip"} {
		r := &Raw{profile: profile, isClient: true}
		r.setSportMode(false, 4500)
		if r.sportFix != 0 || r.cport() != 0 {
			t.Errorf("raw/%s forges no ports: sportFix=%d cport=%d, want 0/0",
				profile, r.sportFix, r.cport())
		}
	}

	r := &Raw{profile: "tcp", isClient: true}
	r.setSportMode(true, 4500)
	if r.sportFix != 0 {
		t.Errorf("a rolling tunnel pinned sportFix=%d — the anti-leak rule would narrow to one port "+
			"while the client redraws across the whole range", r.sportFix)
	}
	if !r.sportRandom {
		t.Error("setSportMode(true, …) did not enable rolling")
	}
	if p := r.cport(); p < rawSportLo || p > rawSportHi {
		t.Errorf("rolled port %d is outside %d:%d", p, rawSportLo, rawSportHi)
	}

	rng := strconv.Itoa(rawSportLo) + ":" + strconv.Itoa(rawSportHi)
	for _, isClient := range []bool{true, false} {
		rule := strings.Join(rawDropMatches(testDst, "tcp", rawServerPort, 4500, isClient, false, true)[0], " ")
		if !strings.Contains(rule, rng) {
			t.Errorf("isClient=%v: rolling mode lost the range %s: %s", isClient, rng, rule)
		}
		if strings.Contains(rule, "4500") {
			t.Errorf("isClient=%v: rolling mode pinned 4500: %s", isClient, rule)
		}
	}
}

// An unset raw_sport must leave every one of those three places exactly as it was.
func TestNoFixedSourcePortKeepsTheDefault(t *testing.T) {
	for _, profile := range []string{"udp", "tcp"} {
		for _, isClient := range []bool{true, false} {
			r := &Raw{profile: profile, isClient: isClient, port: rawServerPort}
			r.setSportMode(false, 0)
			if r.sportFix != 0 || r.cport() != 0 {
				t.Errorf("raw/%s isClient=%v: sportFix=%d cport=%d, want 0/0 so rawPorts uses the default",
					profile, isClient, r.sportFix, r.cport())
			}
			s, d := rawPorts(isClient, r.port, r.cport())
			wantS, wantD := rawServerPort, rawClientPort
			if isClient {
				wantS, wantD = rawClientPort, rawServerPort
			}
			if int(s) != wantS || int(d) != wantD {
				t.Errorf("raw/%s isClient=%v: %d->%d, want %d->%d", profile, isClient, s, d, wantS, wantD)
			}
		}
	}
	for _, isClient := range []bool{true, false} {
		rule := strings.Join(rawDropMatches(testDst, "tcp", rawServerPort, 0, isClient, false, false)[0], " ")
		if !strings.Contains(rule, strconv.Itoa(rawClientPort)) {
			t.Errorf("isClient=%v: the default rule lost the client port %d: %s",
				isClient, rawClientPort, rule)
		}
	}
}
