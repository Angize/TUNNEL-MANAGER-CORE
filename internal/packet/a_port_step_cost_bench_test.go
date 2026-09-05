package packet

// What one packet pays to decide which port it leaves on. Measured on DE02 (go1.25.12, EPYC-Rome,
// 2 cores), -benchtime 3s -count=3, so nobody re-derives it.
//
//   fixed     3.2-4.3 ns serial, 1.4-1.6 parallel   -- wirePorts returns before deciding anything
//   reactive  7.6-9.5 ns serial, 3.7-3.9 parallel   -- an atomic Load and dportAt, no permutation:
//                                                      the client's port is already in cliPort
//   rotation  31-34 ns serial                       -- a 64-bit DIV by sportEvery plus a 4-round
//                                                      Feistel, both per packet
//
// The reactive mode first shared portStep() with the rotation and so paid txCount.Add(1) per packet
// for a counter it never reads. That cost 16.1 ns parallel, 4.2x what it costs now: one contended
// read-modify-write on a cache line every worker touches. The branch that skips it is the fix.
//
// The rotation's 30 ns is the divide, and it is NOT addressed here -- sportEvery is fixed for the
// life of the tunnel, so a counter would replace the DIV, but that is the shipped rotation's hot path
// and belongs in its own change.
//
// The tcp profile costs the same as udp in every mode, which is the point of them being one feature:
//
//   fixed      udp 3.8-4.0    tcp 3.8-4.0 ns
//   reactive   udp 8.5-9.3    tcp 8.6-9.4 ns
//   rotation   udp 31.5-33.8  tcp 31.5-32.2 ns
//
// rotActive() is 0.40-0.43 ns because the profile is checked where the knob is ARMED, not on every
// packet. Re-deriving it per packet through RawProfileHasPorts costs a string map lookup, and there
// is nothing to re-derive: sportEvery is only ever set by setSportRotate, which refuses a profile
// that forges no ports.

import "testing"

func benchRawProfile(profile string, sportRandom bool, every int) *Raw {
	proto := protoUDP
	if profile == "tcp" {
		proto = protoTCP
	}
	r := &Raw{profile: profile, proto: proto, isClient: true, port: 443, psk: "a-psk"}
	r.setSportMode(sportRandom, 0)
	r.setSportRotate(SportRotation{Every: every})
	return r
}

func benchRaw(sportRandom bool, every int) *Raw {
	return benchRawProfile("udp", sportRandom, every)
}

func BenchmarkWirePortsFixed(b *testing.B) {
	r := benchRaw(false, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkWirePortsReactive(b *testing.B) {
	r := benchRaw(true, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkWirePortsRotation(b *testing.B) {
	r := benchRaw(false, 4)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkWirePortsReactiveParallel(b *testing.B) {
	r := benchRaw(true, 0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = r.wirePorts(40000)
		}
	})
}

func BenchmarkWirePortsFixedParallel(b *testing.B) {
	r := benchRaw(false, 0)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = r.wirePorts(40000)
		}
	})
}

func BenchmarkWirePortsTcpFixed(b *testing.B) {
	r := benchRawProfile("tcp", false, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkWirePortsTcpReactive(b *testing.B) {
	r := benchRawProfile("tcp", true, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkWirePortsTcpRotation(b *testing.B) {
	r := benchRawProfile("tcp", false, 4)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.wirePorts(40000)
	}
}

func BenchmarkRotActive(b *testing.B) {
	r := benchRawProfile("tcp", false, 4)
	n := 0
	for i := 0; i < b.N; i++ {
		if r.rotActive() {
			n++
		}
	}
	if n != b.N {
		b.Fatal("rotActive went false mid-run")
	}
}
