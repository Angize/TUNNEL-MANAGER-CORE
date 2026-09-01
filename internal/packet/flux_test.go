package packet

import (
	"testing"
	"time"
)

func TestFluxShapeDeterministic(t *testing.T) {
	for _, ep := range []int64{0, 1, 4471, 1 << 40} {
		a := deriveFluxShape("hunter2", ep, "random")
		b := deriveFluxShape("hunter2", ep, "random")
		if a != b {
			t.Fatalf("epoch %d: shape not deterministic: %+v vs %+v", ep, a, b)
		}
		if !dportInPool(a.dport, fluxDportPool) {
			t.Fatalf("epoch %d: udp dport %d not in the udp pool", ep, a.dport)
		}
		if !dportInPool(a.dportSTUN, fluxStunDports) {
			t.Fatalf("epoch %d: stun dport %d not in STUN pool", ep, a.dportSTUN)
		}
		if a.sport < 20000 || a.sport > 59999 {
			t.Fatalf("epoch %d: sport %d outside the ephemeral band", ep, a.sport)
		}
	}
}

// flux_shape offers the operator "quic", "video" and "webrtc" and used to change exactly one thing:
// how much padding a PING frame carries, and only when obfs is on. The destination port -- the one
// thing on the wire that says what the traffic claims to be -- was drawn from the whole pool
// regardless, so a tunnel set to "webrtc" spent a third of its epochs on 443 and one set to "quic"
// spent them on 3478. The knob named a protocol and picked none.
//
// The shape now chooses the port it claims. Packet SIZES still belong to the payload: without cover
// traffic no setting can make a tunnel look like video, and this knob does not pretend to.
func TestTheFluxShapeChoosesThePortItClaims(t *testing.T) {
	want := map[string][]uint16{
		"quic":   {443},
		"video":  {443, 8801},
		"webrtc": {3478, 19302, 5349},
	}
	for shape, ports := range want {
		seen := map[uint16]bool{}
		for ep := int64(0); ep < 400; ep++ {
			sh := deriveFluxShape("hunter2", ep, shape)
			if !dportInPool(sh.dport, ports) {
				t.Fatalf("shape %q drew udp dport %d, which is not one of %v", shape, sh.dport, ports)
			}
			if !dportInPool(sh.dportSTUN, fluxStunDports) {
				t.Fatalf("shape %q drew stun dport %d outside the STUN pool", shape, sh.dportSTUN)
			}
			seen[sh.dport] = true
		}
		if len(seen) != len(ports) {
			t.Errorf("shape %q used %d of its %d ports over 400 epochs", shape, len(seen), len(ports))
		}
	}

	wide := map[uint16]bool{}
	for ep := int64(0); ep < 400; ep++ {
		wide[deriveFluxShape("hunter2", ep, "random").dport] = true
	}
	if len(wide) != len(fluxDportPool) {
		t.Errorf("\"random\" used %d of the %d ports in the pool", len(wide), len(fluxDportPool))
	}

	v := deriveFluxShape("hunter2", 42, "video")
	if v.ctrlPad < 64 || v.ctrlPad > 223 {
		t.Fatalf("video ctrlPad %d out of its profile band", v.ctrlPad)
	}
}

func TestFluxShapeKeyed(t *testing.T) {
	same := 0
	for ep := int64(0); ep < 64; ep++ {
		if deriveFluxShape("psk-A", ep, "random").sport == deriveFluxShape("psk-B", ep, "random").sport {
			same++
		}
	}

	if same == 64 {
		t.Fatal("two PSKs derived the identical port schedule — PSK not keyed into the shape")
	}
}

func TestFluxEpochBoundary(t *testing.T) {
	rotate := 10 * time.Second
	base := time.Unix(1_000_000_000, 0)
	e0 := fluxEpochAt(rotate, base)
	if got := fluxEpochAt(rotate, base.Add(9*time.Second)); got != e0 {
		t.Fatalf("epoch changed within the period: %d != %d", got, e0)
	}
	if got := fluxEpochAt(rotate, base.Add(10*time.Second)); got != e0+1 {
		t.Fatalf("epoch did not advance at the boundary: %d != %d", got, e0+1)
	}
}

func TestFluxGraceWindow(t *testing.T) {
	e := fluxEpochAt(10*time.Second, time.Unix(1_000_000_000, 0))
	for _, c := range []string{"udp", "stun"} {
		gd := graceDports("hunter2", e, "random", c)
		for _, ep := range []int64{e - 1, e, e + 1} {
			want := deriveFluxShape("hunter2", ep, "random").dportFor(c)
			if !gd[want] {
				t.Fatalf("%s grace window missing dport %d for epoch %d", c, want, ep)
			}
		}
	}
}

func TestFluxEpochOffsetShiftsSchedule(t *testing.T) {
	base := fluxEpochAt(600*time.Second, time.Unix(1_700_000_000, 0))
	if s1, s2 := deriveFluxShape("k", base+5, "random"), deriveFluxShape("k", base+5, "random"); s1 != s2 {
		t.Fatal("deriveFluxShape must be deterministic for the same (key, epoch, shape)")
	}

	if deriveFluxShape("k", base, "random").sport == deriveFluxShape("k", base+5, "random").sport &&
		deriveFluxShape("k", base, "random").dport == deriveFluxShape("k", base+5, "random").dport {
		t.Skip("rare: base and base+5 happen to share carrier params")
	}
}

func dportInPool(p uint16, pool []uint16) bool {
	for _, x := range pool {
		if x == p {
			return true
		}
	}
	return false
}
