package packet

import "testing"

// The published pair is what the node keys its verdict on, so it must name what the CARRIER is on --
// never what the cursor has stepped to while a warm dial is still being built.
func TestThePublishedPairIsNotCorruptedByARotationStep(t *testing.T) {
	hosts := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	b, p := edgeCarrier(t, []string{"1.1.1.1", "2.2.2.2"}, hosts)

	ip0, sni0, ok := p.current()
	if !ok {
		t.Fatal("current: pool empty")
	}
	b.pretendConnected(sni0.host, ip0)
	if low, high := b.livePairNow(); low != sni0.host || high != ip0 {
		t.Fatalf("the connected pair is %s · %s, want %s · %s", high, low, ip0, sni0.host)
	}

	p.advance()
	ipN, sniN, _ := p.current()
	if ipN == ip0 && sniN.host == sni0.host {
		t.Fatal("test setup: the rotation step resolved back to the live edge")
	}
	if low, high := b.livePairNow(); low != sni0.host || high != ip0 {
		t.Fatalf("a rotation step moved the published pair to %s · %s while the carrier is still on "+
			"%s · %s — a verdict arriving now would burn the pair nothing measured", high, low, ip0, sni0.host)
	}
	if got := b.readStatus(t).Pair; got.Low != sni0.host || got.High != ip0 {
		t.Fatalf("and the file the node reads says %+v", got)
	}

	b.pretendConnected(sniN.host, ipN)
	if low, high := b.livePairNow(); low != sniN.host || high != ipN {
		t.Fatalf("after landing: %s · %s, want %s · %s", high, low, ipN, sniN.host)
	}
}
