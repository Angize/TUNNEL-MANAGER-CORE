package packet

import (
	"strings"
	"testing"
)

// FEC and the source-port rotation were refused together on the claim that "the FEC send path does
// not cycle the source port per packet". That was never true: the emit path has gone through wire(),
// which calls wirePorts(), since 2026-07-08 -- two months before the refusal was written on
// 2026-09-02. A netns run with the refusal lifted showed eight distinct source ports on the wire with
// both features on, and at 20% loss the pair carried 254 Mbit against 132 with rotation alone, so the
// repair works while the port moves.
//
// This pins the mechanism rather than the measurement: every shard of a block is stamped by the same
// wirePorts() the ordinary send path uses, so whatever the rotation is doing, the FEC shards do it too.
func TestTheFecPathWalksThePortsLikeEverythingElse(t *testing.T) {
	body := funcBody(t, "raw_linux.go", "func (r *Raw) sendFecBlock(")
	if !strings.Contains(body, "r.wire(") {
		t.Fatal("sendFecBlock does not go through wire(), so its shards would not follow the rotation")
	}

	r := &Raw{profile: "udp", proto: protoUDP, isClient: true, port: 443, psk: "a-psk"}
	r.setSportRotate(SportRotation{Every: 2})
	if !r.rotActive() {
		t.Fatal("setup: the rotation is not armed")
	}
	seen := map[uint16]bool{}
	for i := 0; i < 12; i++ {
		srv, cli := r.wirePorts(r.cport())
		sport, _ := rawPorts(true, srv, cli)
		seen[sport] = true
	}
	if len(seen) < 4 {
		t.Errorf("twelve shards at every=2 used %d distinct source ports; the walk is not moving", len(seen))
	}
}

// The geometry knobs must reach the codec unchanged, whatever else is on. A tunnel that asks for 16+4
// and silently gets 10+3 would look fine and protect less than the operator was told.
func TestTheGeometryAsksForIsTheGeometryItGets(t *testing.T) {
	for _, g := range []struct{ n, k int }{{10, 2}, {10, 3}, {16, 4}, {20, 2}, {8, 4}} {
		var blocks int
		enc, dec := newFecPair(true, g.n, g.k, "a-psk", "geo",
			func(b [][]byte) { blocks++ }, func([]byte) {})
		if enc == nil || dec == nil {
			t.Fatalf("%d+%d: no pair", g.n, g.k)
		}
		if enc.n != g.n || enc.k != g.k {
			t.Errorf("asked for %d+%d, the encoder has %d+%d", g.n, g.k, enc.n, enc.k)
		}
		if enc.codec.n != g.n || enc.codec.k != g.k {
			t.Errorf("asked for %d+%d, the codec has %d+%d", g.n, g.k, enc.codec.n, enc.codec.k)
		}
		for i := 0; i < g.n; i++ {
			enc.addData([]byte("frame"))
		}
		if blocks != 1 {
			t.Errorf("%d+%d: %d blocks left for n frames, want 1", g.n, g.k, blocks)
		}
		enc.Close()
	}
}
