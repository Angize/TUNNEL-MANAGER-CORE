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
	b.pretendConnected(ip0, sni0.host)
	if low, high := b.livePairNow(); low != ip0 || high != sni0.host {
		t.Fatalf("the connected pair is %s · %s, want %s · %s", low, high, ip0, sni0.host)
	}

	p.advance()
	ipN, sniN, _ := p.current()
	if ipN == ip0 && sniN.host == sni0.host {
		t.Fatal("test setup: the rotation step resolved back to the live edge")
	}
	if low, high := b.livePairNow(); low != ip0 || high != sni0.host {
		t.Fatalf("a rotation step moved the published pair to %s · %s while the carrier is still on "+
			"%s · %s — a verdict arriving now would burn the pair nothing measured", low, high, ip0, sni0.host)
	}
	if got := b.readStatus(t).Pair; got.Low != ip0 || got.High != sni0.host {
		t.Fatalf("and the file the node reads says %+v", got)
	}

	b.pretendConnected(ipN, sniN.host)
	if low, high := b.livePairNow(); low != ipN || high != sniN.host {
		t.Fatalf("after landing: %s · %s, want %s · %s", low, high, ipN, sniN.host)
	}
}
