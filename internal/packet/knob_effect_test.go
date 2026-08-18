package packet

import (
	"testing"
)

func TestFakeModeIgnoresSplitTTL(t *testing.T) {
	for _, ttl := range []int{0, 1, 4, 5, 64, 255} {
		f := newFragConn(nil, "example.com", 0, sniFakeMode, ttl, false, nil)
		if got := f.fakeSegTTL(); got != fakeTTL {
			t.Fatalf("split_ttl=%d gave the decoy TTL %d, want fake mode's own %d — a stored disorder "+
				"value must not reach the decoy", ttl, got, fakeTTL)
		}
	}
	if fakeTTL <= disorderTTL {
		t.Fatalf("fake mode's TTL (%d) must be well above the disorder TTL (%d) — the decoy has to "+
			"outlive the hops disorder's head segment is meant to die within", fakeTTL, disorderTTL)
	}

	d := newFragConn(nil, "example.com", 0, sniDisorderMode, 5, false, nil)
	if d.ttl != 5 {
		t.Fatalf("disorder must still carry the operator's split_ttl, got %d", d.ttl)
	}

	b := &TCP{isClient: true, ws: true}
	if !b.SetSNISplit(true, 0, sniFakeMode, 4) {
		t.Fatal("a ws carrier must accept sni_split")
	}
	if got := b.fragWrap(nil, "example.com", nil).(*fragConn).fakeSegTTL(); got != fakeTTL {
		t.Fatalf("through the carrier, a stored split_ttl=4 produced decoy TTL %d, want %d", got, fakeTTL)
	}
}

func TestSetSNISplitReportsWhetherItApplied(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    *TCP
		want bool
	}{
		{"ws client", &TCP{isClient: true, ws: true}, true},
		{"plain tcp client", &TCP{isClient: true}, false},
		{"ws server", &TCP{ws: true}, false},
	} {
		if got := tc.b.SetSNISplit(true, 0, sniSplitMode, 0); got != tc.want {
			t.Fatalf("%s: SetSNISplit reported %v, want %v", tc.name, got, tc.want)
		}
		if tc.b.sniSplit != tc.want {
			t.Fatalf("%s: reported %v but stored sniSplit=%v — the report must match what was applied",
				tc.name, tc.want, tc.b.sniSplit)
		}
	}
}
