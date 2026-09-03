//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// The destination port is the second axis of the flow-table key. Measured on the burned path
// 2026-09-03: a tuple burned to its 6-packet budget on one destination port delivered 6 of 6 again
// from the SAME source port to a different one, three times out of three. So spreading the client's
// destination port multiplies the number of buckets a source port is worth, which is the ceiling.
// The set always opens with the port the operator configured, so one destination is exactly today.
func TestTheDestinationSetIsKeyedAndOpensWithTheConfiguredPort(t *testing.T) {
	for _, n := range []int{-1, 0, 1} {
		if got := dportSet(443, n, "psk"); len(got) != 1 || got[0] != 443 {
			t.Errorf("dportSet(443, %d) = %v, want just the configured port", n, got)
		}
	}
	for _, base := range []uint16{443, 4500, 51820} {
		for n := 2; n <= MaxDports; n++ {
			got := dportSet(base, n, "a-preshared-key")
			if len(got) != n {
				t.Errorf("dportSet(%d, %d) returned %d ports", base, n, len(got))
			}
			if got[0] != base {
				t.Errorf("dportSet(%d, %d) opens with %d, not the configured port", base, n, got[0])
			}
			seen := map[uint16]bool{}
			for _, p := range got {
				if seen[p] {
					t.Errorf("dportSet(%d, %d) = %v repeats %d, which wastes a whole lap", base, n, got, p)
				}
				seen[p] = true
				if p == 0 {
					t.Errorf("dportSet(%d, %d) drew 0, which rawPorts reads as \"use the default\"", base, n)
				}
			}
		}
	}
	if got := dportSet(443, MaxDports+9, "psk"); len(got) != MaxDports {
		t.Errorf("asking for more than the pool holds returned %d ports, want %d", len(got), MaxDports)
	}

	// the pool is a package-level array; building a set must not shuffle it in place
	before := dportPool
	dportSet(443, MaxDports, "some-other-key")
	if dportPool != before {
		t.Fatalf("dportSet reordered the shared pool: %v -> %v", before, dportPool)
	}

	a, b := dportSet(443, 4, "one-key"), dportSet(443, 4, "another-key-entirely")
	same := 0
	for i := range a {
		if a[i] == b[i] {
			same++
		}
	}
	if same == len(a) {
		t.Errorf("two PSKs produced the identical set %v; the pool order is not keyed", a)
	}
}

// The whole point: a (source, destination) pair must not come back until every destination has been
// walked with the whole band. One destination is one band; K destinations is K bands.
func TestATupleComesBackOnlyAfterEveryDestinationHasHadTheWholeBand(t *testing.T) {
	const k = 3
	r := rotClient(1, k)
	if len(r.dports) != k {
		t.Fatalf("client armed with %d destinations, want %d", len(r.dports), k)
	}
	seen := make(map[uint32]bool, sportBandSpan*k)
	var first uint32
	for i := 0; i < sportBandSpan*k; i++ {
		dp, sp := r.wirePorts(51820)
		key := uint32(sp)<<16 | uint32(dp)
		if seen[key] {
			t.Fatalf("tuple %d->%d came back after %d draws, want %d", sp, dp, i, sportBandSpan*k)
		}
		seen[key] = true
		if i == 0 {
			first = key
		}
	}
	dp, sp := r.wirePorts(51820)
	if uint32(sp)<<16|uint32(dp) != first {
		t.Errorf("the walk did not close its cycle at %d draws", sportBandSpan*k)
	}
}

// wirePorts is what actually reaches rawEncap, so the roles are asserted on the built frame rather
// than on the helper that feeds it.
func TestOnlyTheClientSpreadsItsDestinationAndTheServerAnswersWhereItWasAsked(t *testing.T) {
	dst := net.IPv4(203, 0, 113, 9)
	build := func(r *Raw) (uint16, uint16) {
		srv, cli := r.wirePorts(r.cport())
		pkt := rawEncap("udp", []byte("payload"), testSrc, dst, r.isClient, 0, srv, cli, 0, 0, 0, 0, 0, 0)
		return binary.BigEndian.Uint16(pkt[0:2]), binary.BigEndian.Uint16(pkt[2:4])
	}

	// one destination is exactly today's wire: every packet aims at the configured port
	one := rotClient(4, 1)
	for i := 0; i < 400; i++ {
		if _, dp := build(one); dp != rawServerPort {
			t.Fatalf("packet %d went to %d with one destination configured, want %d", i, dp, rawServerPort)
		}
	}

	const k = 4
	many := rotClient(1, k)
	got := map[uint16]bool{}
	for i := 0; i < sportBandSpan*k; i++ {
		_, dp := build(many)
		got[dp] = true
	}
	if len(got) != k {
		t.Errorf("the client used %d destination ports over %d laps, want %d", len(got), k, k)
	}
	for _, want := range many.dports {
		if !got[want] {
			t.Errorf("destination %d was armed but never reached the wire", want)
		}
	}

	const learned = 51820
	srv := rotServer(4, learned)
	srv.dports = dportSet(rawServerPort, k, "a-preshared-key")
	for i := 0; i < 200; i++ {
		sp, dp := build(srv)
		if dp != learned {
			t.Fatalf("the server answered to %d, not the port the client asked from (%d)", dp, learned)
		}
		if uint32(sp) < sportBandLo || uint32(sp) >= sportBandLo+sportBandSpan {
			t.Fatalf("the server's own source %d left the band", sp)
		}
	}
}

// The card prints what the status says, so a server that reported its configured port as the
// destination would be telling the operator about a port it never sends to.
func TestTheStatusNamesTheDestinationThisEndActuallySendsTo(t *testing.T) {
	c := rotClient(4, 3)
	for i := 0; i < 9; i++ {
		c.wirePorts(51820)
	}
	st := c.rotSnapshot()
	if st.Dports != 3 {
		t.Errorf("client status says %d destinations, want 3", st.Dports)
	}
	found := false
	for _, d := range c.dports {
		found = found || d == st.Dport
	}
	if !found {
		t.Errorf("client status names destination %d, which is not in %v", st.Dport, c.dports)
	}

	const learned = 40404
	s := rotServer(4, learned)
	if got := s.rotSnapshot().Dport; got != learned {
		t.Errorf("server status names destination %d, want the learned client port %d", got, learned)
	}
}
