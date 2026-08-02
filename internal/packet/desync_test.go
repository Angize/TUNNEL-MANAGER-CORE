//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestNewDesyncCfgDefaults locks in the defaulting (mirrors the node/panel defaults).
func TestNewDesyncCfgDefaults(t *testing.T) {
	if d := newDesyncCfg(false, 9, 9, "both"); d.on {
		t.Fatal("off flag must yield the zero (off) config regardless of other args")
	}
	d := newDesyncCfg(true, 0, 0, "")
	if !d.on || d.ttl != 4 || d.count != 2 || d.mode != "ttl" {
		t.Fatalf("defaults wrong: %+v (want on ttl=4 count=2 mode=ttl)", d)
	}
	if got := newDesyncCfg(true, 7, 5, "garbage"); got.mode != "ttl" {
		t.Fatalf("unknown mode must fall back to ttl, got %q", got.mode)
	}
	if got := newDesyncCfg(true, 7, 5, "badsum"); got.ttl != 7 || got.count != 5 || got.mode != "badsum" {
		t.Fatalf("explicit values not preserved: %+v", got)
	}
}

// TestDesyncSpecs checks the per-decoy header knobs for each mode: a ttl decoy keeps a live
// checksum + the low TTL; a badsum decoy keeps a normal TTL; "both" alternates.
func TestDesyncSpecs(t *testing.T) {
	if s := (desyncCfg{}).specs(); s != nil {
		t.Fatal("off config must produce no specs")
	}
	ttlS := newDesyncCfg(true, 3, 3, "ttl").specs()
	if len(ttlS) != 3 {
		t.Fatalf("ttl mode: want 3 specs, got %d", len(ttlS))
	}
	for i, s := range ttlS {
		if s.badSum || s.ttl != 3 {
			t.Fatalf("ttl spec %d wrong: %+v", i, s)
		}
	}
	badS := newDesyncCfg(true, 3, 2, "badsum").specs()
	for i, s := range badS {
		if !s.badSum || s.ttl != 64 {
			t.Fatalf("badsum spec %d wrong: %+v (want badSum + ttl 64)", i, s)
		}
	}
	bothS := newDesyncCfg(true, 5, 4, "both").specs()
	if len(bothS) != 4 {
		t.Fatalf("both mode: want 4 specs, got %d", len(bothS))
	}
	// even index -> ttl decoy (low ttl, good sum); odd -> badsum decoy (ttl 64, bad sum)
	for i, s := range bothS {
		if i%2 == 0 && (s.badSum || s.ttl != 5) {
			t.Fatalf("both spec %d (even) should be a ttl decoy: %+v", i, s)
		}
		if i%2 == 1 && (!s.badSum || s.ttl != 64) {
			t.Fatalf("both spec %d (odd) should be a badsum decoy: %+v", i, s)
		}
	}
}

// TestBuildIP4Ext verifies the header fields, that a good checksum verifies to zero, and that badSum
// deliberately breaks it. buildIP4 IS buildIP4Ext(ttl=64, badSum=false) in everything except the two
// fields that are per-packet by design — the Identification, and the checksum that follows from it — so
// the equivalence is stated field-wise rather than as byte-identity.
func TestBuildIP4Ext(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 0, 2)
	payload := []byte("hello desync")

	base := buildIP4(src, dst, protoBIP, payload)
	ext := buildIP4Ext(src, dst, protoBIP, 64, false, payload)
	if len(base) != len(ext) {
		t.Fatalf("lengths differ: %d vs %d", len(base), len(ext))
	}
	for i := range base {
		if i >= 4 && i < 6 { // Identification: different every packet, deliberately
			continue
		}
		if i >= 10 && i < 12 { // header checksum: follows the Identification
			continue
		}
		if base[i] != ext[i] {
			t.Fatalf("byte %d differs (%#x vs %#x): buildIP4 must stay buildIP4Ext(ttl=64, badSum=false) "+
				"in every field except the ones that are per-packet by design", i, base[i], ext[i])
		}
	}
	if base[8] != 64 {
		t.Fatalf("default TTL byte = %d, want 64", base[8])
	}
	if base[9] != byte(protoBIP) {
		t.Fatalf("proto byte = %d, want %d", base[9], protoBIP)
	}
	// A valid IPv4 header sums (one's complement, including the stored checksum) to zero.
	if s := onesComplementSum(base[:20]); s != 0 {
		t.Fatalf("valid header checksum should verify to 0, got %#04x", s)
	}

	low := buildIP4Ext(src, dst, protoBIP, 3, false, payload)
	if low[8] != 3 {
		t.Fatalf("low-TTL header TTL = %d, want 3", low[8])
	}
	if s := onesComplementSum(low[:20]); s != 0 {
		t.Fatalf("low-TTL header must still have a VALID checksum, got %#04x", s)
	}

	bad := buildIP4Ext(src, dst, protoBIP, 64, true, payload)
	if s := onesComplementSum(bad[:20]); s == 0 {
		t.Fatal("badSum header must NOT verify (checksum should be corrupted)")
	}
	// The only difference from a good header is the checksum field — everything else identical.
	good := buildIP4Ext(src, dst, protoBIP, 64, false, payload)
	if binary.BigEndian.Uint16(bad[10:12]) == binary.BigEndian.Uint16(good[10:12]) {
		t.Fatal("badSum checksum must differ from the correct one")
	}
	// Normalise the two fields that are per-packet by design (the Identification, and therefore the
	// checksum) and require everything else to match: badSum must touch the checksum and nothing else.
	copy(bad[4:6], good[4:6])
	copy(bad[10:12], good[10:12])
	if string(bad) != string(good) {
		t.Fatal("badSum must corrupt ONLY the checksum field, nothing else")
	}
}

// TestBuildIP4ExtBadSumZeroTwin locks in the one's-complement zero-twin case: when the correct header
// checksum is 0x0000 its complement 0xffff ALSO verifies, so a naive ^sum would leave a VALID checksum.
// Identification is per-packet and contributes linearly to the sum, so for a fixed header exactly one ID
// produces the twin. The counter is package-level and is searched exhaustively — no probability involved.
func TestBuildIP4ExtBadSumZeroTwin(t *testing.T) {
	src := net.IPv4(10, 0, 0, 0)
	dst := net.IPv4(192, 168, 1, 0)
	payload := make([]byte, 69)

	saved := ipIDCounter.Load()
	defer ipIDCounter.Store(saved)
	found := false
	for id := 0; id <= 0xffff; id++ {
		ipIDCounter.Store(uint32(id) - 1) // nextIPID adds 1 before returning
		if binary.BigEndian.Uint16(buildIP4Ext(src, dst, protoBIP, 238, false, payload)[10:12]) == 0x0000 {
			ipIDCounter.Store(uint32(id) - 1)
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no Identification value makes this header sum to the 0x0000 twin — the test premise " +
			"is broken, not the code")
	}
	good := buildIP4Ext(src, dst, protoBIP, 238, false, payload)
	if binary.BigEndian.Uint16(good[10:12]) != 0x0000 {
		t.Fatalf("test premise broken: correct checksum should be 0x0000, got %#04x", binary.BigEndian.Uint16(good[10:12]))
	}
	ipIDCounter.Store(ipIDCounter.Load() - 1) // rebuild the SAME header for the badSum twin
	if onesComplementSum(good[:20]) != 0 {
		t.Fatal("the 0x0000-checksum header must itself verify")
	}
	bad := buildIP4Ext(src, dst, protoBIP, 238, true, payload)
	if onesComplementSum(bad[:20]) == 0 {
		t.Fatalf("badSum header STILL verifies (zero-twin not handled): checksum=%#04x", binary.BigEndian.Uint16(bad[10:12]))
	}
}

// TestBuildIP4ExtTTLClamp checks the TTL is clamped into 1..255 (a 0 or negative TTL would
// be an instantly-dead packet or a malformed byte).
func TestBuildIP4ExtTTLClamp(t *testing.T) {
	src, dst := net.IPv4(1, 1, 1, 1), net.IPv4(2, 2, 2, 2)
	if p := buildIP4Ext(src, dst, protoUDP, 0, false, nil); p[8] != 1 {
		t.Fatalf("ttl 0 should clamp to 1, got %d", p[8])
	}
	if p := buildIP4Ext(src, dst, protoUDP, 999, false, nil); p[8] != 255 {
		t.Fatalf("ttl 999 should clamp to 255, got %d", p[8])
	}
}

// TestSpecsTCP checks the kernel-TCP inject path keeps EVERY decoy at the low TTL (never the
// 64 that specs() promotes badsum to), because a well-formed segment on a real 4-tuple must not
// reach the server. badSum still varies per mode.
func TestSpecsTCP(t *testing.T) {
	both := newDesyncCfg(true, 3, 4, "both").specsTCP()
	if len(both) != 4 {
		t.Fatalf("want 4 specs, got %d", len(both))
	}
	for i, s := range both {
		if s.ttl != 3 {
			t.Fatalf("specsTCP decoy %d has ttl %d, want the low 3 (never promoted to 64)", i, s.ttl)
		}
		wantBad := i%2 == 1
		if s.badSum != wantBad {
			t.Fatalf("specsTCP decoy %d badSum=%v, want %v", i, s.badSum, wantBad)
		}
	}
	for _, s := range newDesyncCfg(true, 5, 2, "badsum").specsTCP() {
		if s.ttl != 5 || !s.badSum {
			t.Fatalf("badsum-mode TCP spec should be low-ttl + badSum, got %+v", s)
		}
	}
	// A high fake_ttl must be clamped on the inject path so a well-formed decoy can't reach the
	// server (it would draw an RST / challenge-ACK on the real 4-tuple).
	for i, s := range newDesyncCfg(true, 64, 3, "both").specsTCP() {
		if s.ttl != injectMaxTTL {
			t.Fatalf("specsTCP decoy %d: ttl 64 should clamp to %d, got %d", i, injectMaxTTL, s.ttl)
		}
	}
	// Pin the wire to the ceiling TCP.SetDesync announces (TestSetDesyncReportsTheCappedTTL). If the
	// two ever drift, the log goes back to describing a hop budget the wire does not carry — which is
	// the defect that made the cap invisible in the first place, one layer down.
	for _, ttl := range []int{1, 4, injectMaxTTL, injectMaxTTL + 1, 30, 255} {
		want := ttl
		if want > injectMaxTTL {
			want = injectMaxTTL
		}
		for i, s := range newDesyncCfg(true, ttl, 3, "both").specsTCP() {
			if s.ttl != want {
				t.Errorf("fake_ttl=%d decoy %d: wire ttl %d, want %d", ttl, i, s.ttl, want)
			}
		}
	}
}

// TestBuildTCPSeg checks the crafted segment has the right ports/flags and a VALID TCP checksum
// (recomputing over the segment with the stored checksum in place sums to zero).
func TestBuildTCPSeg(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(10, 0, 1, 2)
	seg := buildTCPSeg(src, dst, 40000, 443, 0x11223344, 0x55667788, tcpPshAck, 0xffff, nil, []byte("decoy-body"))
	if binary.BigEndian.Uint16(seg[0:2]) != 40000 || binary.BigEndian.Uint16(seg[2:4]) != 443 {
		t.Fatal("ports not stamped correctly")
	}
	if seg[13] != tcpPshAck {
		t.Fatalf("flags = %#x, want PSH|ACK %#x", seg[13], tcpPshAck)
	}
	if binary.BigEndian.Uint32(seg[4:8]) != 0x11223344 || binary.BigEndian.Uint32(seg[8:12]) != 0x55667788 {
		t.Fatal("seq/ack not stamped")
	}
	// A valid TCP checksum: the pseudo-header + segment (checksum in place) one's-complement to 0.
	if s := l4Checksum(src, dst, protoTCP, seg); s != 0 {
		t.Fatalf("TCP checksum should verify to 0, got %#04x", s)
	}
}

// TestFakePayload checks the decoy payload stays in the intended plausible-frame size band.
func TestFakePayload(t *testing.T) {
	for i := 0; i < 200; i++ {
		n := len(fakePayload())
		if n < 48 || n > 111 {
			t.Fatalf("fakePayload len %d out of the 48..111 band", n)
		}
	}
}

// TestDecoySeqDistinct guards that the decoys of ONE batch carry DISTINCT sequence numbers: previously
// every decoy read the same r.seq/r.tcpBytes, so a batch was N byte-for-byte-header packets (and on
// icmp, N identical id+seq echo requests — a cheap signature). Pure over the seq state, no socket.
func TestDecoySeqDistinct(t *testing.T) {
	for _, proto := range []int{protoICMP, protoTCP, protoBIP} {
		r := &Raw{proto: proto}
		r.seq.Store(500)
		r.tcpBytes.Store(9000)
		seen := map[uint32]bool{}
		for i := 0; i < 8; i++ {
			s := r.decoySeq(i)
			if seen[s] {
				t.Fatalf("proto %d: decoy %d repeats seq %d — a batch must not carry identical sequences", proto, i, s)
			}
			seen[s] = true
			// icmp stamps uint16(seq); check the low 16 bits stay distinct too (that is what is on the wire).
			if proto == protoICMP {
				lo := uint16(s)
				for j := 0; j < i; j++ {
					if uint16(r.decoySeq(j)) == lo {
						t.Fatalf("icmp decoy %d and %d share the on-wire uint16 seq %d", i, j, lo)
					}
				}
			}
		}
	}
}

// TestDecoySeqNeverAliasesTheLiveStream closes the half TestDecoySeqDistinct does not: that one proves
// the decoys of a batch differ from EACH OTHER, and stays green while every decoy carries the live
// stream's own on-wire sequence. The icmp profile stamps only uint16(seq), so the gap must be far from
// zero modulo 2^16 as well as large in the 32-bit space, or a middlebox reads a real frame as a duplicate.
func TestDecoySeqNeverAliasesTheLiveStream(t *testing.T) {
	const live = 41000
	r := &Raw{proto: protoICMP}
	r.seq.Store(live)

	// The frames around this handshake: the one just sent (live) and the next ones the stream will send
	// (writeOut does r.seq.Add(1) per frame). No decoy of the batch may collide with any of them.
	window := map[uint16]int{}
	for n := 0; n < 64; n++ {
		window[uint16(live+uint32(n))] = n
	}
	for i := 0; i < 8; i++ {
		lo := uint16(r.decoySeq(i))
		if n, clash := window[lo]; clash {
			t.Fatalf("icmp decoy %d stamps on-wire seq %d, which is the live stream's frame +%d — "+
				"a middlebox tracking (id, seq) can take the real frame for a duplicate", i, lo, n)
		}
	}

	// State the property directly, so a future change to fakeSeqGap cannot quietly reintroduce it: the
	// offset must not vanish in the 16-bit field the icmp profile actually puts on the wire.
	if fakeSeqGap%(1<<16) == 0 {
		t.Fatalf("fakeSeqGap=%d is a multiple of 2^16, so uint16(seq+gap)==uint16(seq): the icmp "+
			"profile gets no offset at all", fakeSeqGap)
	}

	// The tcp profile uses the full uint32, so the gap must still be large there.
	rt := &Raw{proto: protoTCP}
	rt.tcpBytes.Store(9000)
	if d := rt.decoySeq(0) - (rt.tcpISN + rt.tcpBytes.Load()); d < 1<<16 {
		t.Fatalf("tcp decoy offset %d is too small to stay clear of the live byte stream", d)
	}
}
