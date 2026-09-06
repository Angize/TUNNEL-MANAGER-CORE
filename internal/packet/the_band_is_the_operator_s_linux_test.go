package packet

import (
	"testing"
)

// The band the forged source port is drawn from used to be two package constants. It is a per-tunnel
// setting now, because which ports survive a path is a property of THAT path: measured 2026-09-06 on
// one live pair, a source port at or above 48000 was blocked outright into Iran while everything
// below it delivered, and on two other pairs the same ports were clean. A number that is right for
// one tunnel and wrong for the next belongs in the tunnel's config, not in the binary.
//
// Everything here is about the four ways that can go wrong: a draw outside the band, a band that no
// longer covers itself, a permutation domain so much wider than the band that the rejection loop
// runs long on the send path, and a default that quietly stopped being the default.

func bandOf(t *testing.T, lo, hi int) rotPerm {
	t.Helper()
	l, s := sportBand(lo, hi)
	return rotPermFrom("a-sufficiently-long-preshared-key", true, l, s)
}

// A band the operator asks for is the band the wire sees: every draw lands inside it, and a full lap
// covers every port in it exactly once. The second half is what makes the walk a permutation rather
// than a random pick -- without it the same port comes back early and the tuple budget is spent twice.
func TestEveryBandIsCoveredExactlyOnce(t *testing.T) {
	for _, b := range [][2]int{
		{10000, 59999}, // the default
		{10000, 44999}, // below the cliff measured on the burned pair
		{20000, 29999},
		{1024, 1123},   // the lowest legal band: the port floor, exactly MinSportBandSpan wide
		{40000, 40099}, // a narrow band high up
		{1024, 65535},  // as wide as the port space allows
	} {
		lo, hi := b[0], b[1]
		p := bandOf(t, lo, hi)
		if int(p.lo) != lo || int(p.lo+p.span-1) != hi {
			t.Fatalf("band %d-%d became %d-%d", lo, hi, p.lo, p.lo+p.span-1)
		}
		seen := make(map[uint16]bool, p.span)
		for i := uint64(0); i < uint64(p.span); i++ {
			v := p.at(i)
			if int(v) < lo || int(v) > hi {
				t.Fatalf("band %d-%d: index %d drew %d, outside the band", lo, hi, i, v)
			}
			if seen[v] {
				t.Fatalf("band %d-%d: %d came back after %d of %d draws", lo, hi, v, i, p.span)
			}
			seen[v] = true
		}
		if len(seen) != int(p.span) {
			t.Fatalf("band %d-%d: a full lap covered %d ports, want %d", lo, hi, len(seen), p.span)
		}
		// And the lap repeats, rather than the walk wandering into a second sequence.
		if p.at(uint64(p.span)) != p.at(0) {
			t.Fatalf("band %d-%d: the walk did not close its cycle", lo, hi)
		}
	}
}

// at() cycle-walks: it applies the permutation until the value lands inside the band. That loop is on
// the send path, so the domain has to hug the band. A fixed 65536-wide domain would make a 100-port
// band reject 654 times per draw on average.
func TestTheDomainHugsTheBand(t *testing.T) {
	for _, b := range [][2]int{{10000, 59999}, {10000, 44999}, {1024, 1123}, {40000, 40099}, {1024, 65535}} {
		p := bandOf(t, b[0], b[1])
		dom := uint64(1) << (2 * p.halfBits)
		if dom < uint64(p.span) {
			t.Fatalf("band %d-%d: domain %d is smaller than the band, so some ports are unreachable",
				b[0], b[1], dom)
		}
		if dom >= 4*uint64(p.span) {
			t.Fatalf("band %d-%d: domain %d for %d ports rejects %.1fx per draw",
				b[0], b[1], dom, p.span, float64(dom)/float64(p.span))
		}
	}
}

// The default is what a tunnel that says nothing gets, and it has to be the band that was compiled in
// before this was configurable -- same edges AND same permutation domain, so an existing tunnel walks
// the identical sequence of ports and nothing on the wire moves because the knob appeared.
func TestTheDefaultBandIsWhatItAlwaysWas(t *testing.T) {
	lo, span := sportBand(0, 0)
	if lo != 10000 || span != 50000 {
		t.Fatalf("the default band is %d..%d, want 10000..59999", lo, lo+span-1)
	}
	if p := bandOf(t, 0, 0); p.halfBits != 8 {
		t.Fatalf("the default band picks halfBits=%d; it was 8 before the band was configurable, and a"+
			" different domain means a different port sequence for every tunnel already running", p.halfBits)
	}
}

// A band that cannot work is not half-applied. Anything out of range, inverted, or narrower than the
// floor falls back to the whole default rather than to some clamped fragment of what was asked for --
// a tunnel drawing from a two-port "band" would look like it was rotating while it was not.
func TestAnImpossibleBandFallsBackWhole(t *testing.T) {
	dlo, dspan := sportBand(0, 0)
	for _, b := range [][2]int{
		{0, 0},         // nothing configured
		{-5, 40000},    // below the first port
		{1, 65535},     // port 1 is privileged, and a forged carrier has no reason to claim one
		{1023, 40000},  // one below the floor
		{512, 1023},    // wholly inside the privileged range
		{40000, 70000}, // past the last port
		{50000, 40000}, // inverted
		{30000, 30000}, // one port
		{30000, 30098}, // one short of the floor
		{0, 59999},     // half configured
		{10000, 0},     // the other half
	} {
		lo, span := sportBand(b[0], b[1])
		if lo != dlo || span != dspan {
			t.Errorf("sportBand(%d, %d) = %d..%d, want the default %d..%d",
				b[0], b[1], lo, lo+span-1, dlo, dlo+dspan-1)
		}
	}
	// exactly the floor is legal, and is NOT the fallback
	if lo, span := sportBand(30000, 30099); lo != 30000 || span != MinSportBandSpan {
		t.Errorf("a band of exactly MinSportBandSpan was rejected: %d..%d", lo, lo+span-1)
	}
}

// The two ends key their permutations by role, so they never collide. That was true when the band was
// a constant and has to stay true when it is not -- including inside a narrow band, where there is far
// less room to differ.
func TestTheTwoRolesStillWalkDifferentlyInAnyBand(t *testing.T) {
	for _, b := range [][2]int{{10000, 59999}, {10000, 44999}, {1024, 1123}} {
		l, s := sportBand(b[0], b[1])
		cli := rotPermFrom("a-sufficiently-long-preshared-key", true, l, s)
		srv := rotPermFrom("a-sufficiently-long-preshared-key", false, l, s)
		same := 0
		for i := uint64(0); i < uint64(s); i++ {
			if cli.at(i) == srv.at(i) {
				same++
			}
		}
		// A random pair of permutations collides on about one index in the whole lap; requiring under
		// a twentieth of the band leaves room for that without letting the two walks be the same walk.
		if same > int(s)/20 {
			t.Errorf("band %d-%d: client and server drew the same port at %d of %d indexes",
				b[0], b[1], same, s)
		}
	}
}
