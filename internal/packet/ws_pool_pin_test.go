package packet

import "testing"

func TestPinHeldUntilAppliedThenReleased(t *testing.T) {
	snis := []wsSNIEntry{{host: "a.example"}, {host: "b.example"}}
	p := newWSPool([]string{"1.1.1.1", "2.2.2.2"}, snis)

	var clk int64 = 1000
	p.now = func() int64 { return clk }

	if !p.selectEntry("ip", "2.2.2.2") {
		t.Fatal("selectEntry: unknown key")
	}
	for i := 0; i < 5; i++ {
		clk += 30
		ip, _, ok := p.current()
		if !ok || ip != "2.2.2.2" {
			t.Fatalf("pin not held while unapplied at +%ds: ip=%q", (i+1)*30, ip)
		}
	}

	p.pinLandedOn("2.2.2.2", "a.example")
	if p.pinIP != "" {
		t.Fatalf("pin not cleared after apply: pinIP=%q", p.pinIP)
	}

	if !p.selectEntry("sni", "b.example") {
		t.Fatal("selectEntry sni: unknown key")
	}
	p.pinLandedOn("9.9.9.9", "a.example")
	if p.pinSNI != "b.example" {
		t.Fatalf("non-matching apply wrongly cleared the SNI pin: pinSNI=%q", p.pinSNI)
	}
	p.pinLandedOn("1.1.1.1", "b.example")
	if p.pinSNI != "" {
		t.Fatalf("matching SNI apply did not clear pin: pinSNI=%q", p.pinSNI)
	}

	if !p.selectEntry("ip", "1.1.1.1") {
		t.Fatal("selectEntry: unknown key")
	}
	p.pinCannotLand("1.1.1.1", "")
	if _, _, ok := p.current(); !ok {
		t.Fatal("current: pool empty")
	}
	if p.pinIP != "" {
		t.Fatalf("pin did not self-release past the TTL ceiling: pinIP=%q", p.pinIP)
	}
}
