//go:build linux

package packet

import (
	"strconv"
	"strings"
	"testing"
)

// the_band_is_the_operator_s_linux_test.go asserts things about rotPerm. rotPerm is a HELPER: the
// send path never calls it directly, it calls wirePorts, and the anti-leak rule and the status file
// are built somewhere else again. A band that is right inside rotPerm and wrong in any of those three
// is a tunnel that either leaks RSTs on ports its own rule does not cover, or shows the operator a
// band it is not walking. So this drives the three real callers.

func bandEnd(isClient bool, every, lo, hi int) *Raw {
	r := &Raw{profile: "udp", proto: protoUDP, isClient: isClient, port: 443, psk: "a-psk-for-the-band"}
	r.setBand(lo, hi)
	r.setSportMode(false, 0)
	r.setSportRotate(SportRotation{Every: every, Lo: lo, Hi: hi})
	return r
}

// Every port the SEND PATH stamps is inside the band the operator asked for -- on both roles, because
// each end draws its own source port and a band that only bound the client would leave the server
// walking the compiled-in default.
func TestTheSendPathStaysInsideTheConfiguredBand(t *testing.T) {
	for _, b := range [][2]int{{10000, 44999}, {20000, 29999}, {1024, 1123}, {0, 0}} {
		lo, hi := b[0], b[1]
		wantLo, wantSpan := sportBand(lo, hi)
		for _, isClient := range []bool{true, false} {
			r := bandEnd(isClient, 3, lo, hi)
			seen := map[uint16]bool{}
			for i := 0; i < 4000; i++ {
				srv, cli := r.portsAt(uint64(i), 40000)
				p := srv
				if isClient {
					p = cli
				}
				if uint32(p) < wantLo || uint32(p) >= wantLo+wantSpan {
					t.Fatalf("band %d-%d, client=%v: step %d stamped %d, outside %d-%d",
						lo, hi, isClient, i, p, wantLo, wantLo+wantSpan-1)
				}
				seen[p] = true
			}
			if len(seen) < 2 {
				t.Errorf("band %d-%d, client=%v: the walk stamped %d distinct ports over 4000 steps",
					lo, hi, isClient, len(seen))
			}
		}
	}
}

// The anti-leak rule has to cover the band the send path uses. It is written as one iptables port
// RANGE, so it is exact: a rule narrower than the band drops nothing on the ports outside it, and a
// kernel RST from one of those reaches the peer and tears the forged flow down.
func TestTheAntiLeakRuleCoversExactlyTheBand(t *testing.T) {
	for _, b := range [][2]int{{10000, 44999}, {1024, 1123}, {0, 0}} {
		lo, hi := b[0], b[1]
		wantLo, wantSpan := sportBand(lo, hi)
		r := bandEnd(true, 3, lo, hi)
		l := rawLeak{profile: "tcp", port: r.port, dports: r.dports, isClient: true,
			bandLo: r.rotPerm.lo, bandSpan: r.rotPerm.span, portsMove: r.portsMove()}
		got := l.heardFrom()
		want := strconv.Itoa(int(wantLo)) + ":" + strconv.Itoa(int(wantLo+wantSpan-1))
		if len(got) == 0 || got[0] != want {
			t.Fatalf("band %d-%d: the rule says %v, want it to open with %q", lo, hi, got, want)
		}
		// and a port inside the band is not repeated as a separate spec, while the fixed server port
		// outside it still is -- that second entry is the whole reason the list is not just the range.
		for _, extra := range got[1:] {
			if !strings.Contains(extra, ":") {
				p, err := strconv.Atoi(extra)
				if err != nil {
					t.Fatalf("band %d-%d: rule spec %q is not a port", lo, hi, extra)
				}
				if uint32(p) >= wantLo && uint32(p) < wantLo+wantSpan {
					t.Errorf("band %d-%d: port %d is listed separately AND covered by the range", lo, hi, p)
				}
			}
		}
	}
}

// And the status file reports the band it is actually walking, because that is what the operator
// reads off the card when they are deciding whether to narrow it.
func TestTheStatusReportsTheBandItWalks(t *testing.T) {
	for _, b := range [][2]int{{10000, 44999}, {20000, 29999}, {1024, 1123}, {0, 0}} {
		lo, hi := b[0], b[1]
		wantLo, wantSpan := sportBand(lo, hi)
		r := bandEnd(true, 3, lo, hi)
		s := r.rotSnapshot()
		if uint32(s.Lo) != wantLo || uint32(s.Hi) != wantLo+wantSpan-1 {
			t.Errorf("band %d-%d: the status says %d-%d, want %d-%d",
				lo, hi, s.Lo, s.Hi, wantLo, wantLo+wantSpan-1)
		}
		if uint32(s.Sport) < wantLo || uint32(s.Sport) >= wantLo+wantSpan {
			t.Errorf("band %d-%d: the status reports a live port of %d, outside the band it names",
				lo, hi, s.Sport)
		}
	}
}

// A band the core refuses falls back to the default EVERYWHERE, not just inside rotPerm: the send
// path, the rule and the status all have to agree on the same fallback, or the tunnel walks one band
// while its rule covers another.
func TestAnImpossibleBandFallsBackOnEveryPath(t *testing.T) {
	dlo, dspan := sportBand(0, 0)
	for _, b := range [][2]int{{500, 44999}, {30000, 30050}, {50000, 40000}, {10000, 70000}} {
		r := bandEnd(true, 3, b[0], b[1])
		s := r.rotSnapshot()
		if uint32(s.Lo) != dlo || uint32(s.Hi) != dlo+dspan-1 {
			t.Errorf("band %d-%d: the status says %d-%d, want the default %d-%d",
				b[0], b[1], s.Lo, s.Hi, dlo, dlo+dspan-1)
		}
		l := rawLeak{profile: "tcp", port: r.port, isClient: true,
			bandLo: r.rotPerm.lo, bandSpan: r.rotPerm.span, portsMove: true}
		want := strconv.Itoa(int(dlo)) + ":" + strconv.Itoa(int(dlo+dspan-1))
		if got := l.heardFrom(); got[0] != want {
			t.Errorf("band %d-%d: the rule opens with %q, want the default %q", b[0], b[1], got[0], want)
		}
		for i := 0; i < 500; i++ {
			_, cli := r.portsAt(uint64(i), 40000)
			if uint32(cli) < dlo || uint32(cli) >= dlo+dspan {
				t.Fatalf("band %d-%d: the send path stamped %d, outside the default", b[0], b[1], cli)
			}
		}
	}
}
