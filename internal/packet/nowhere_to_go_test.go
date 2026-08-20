package packet

import (
	"path/filepath"
	"testing"
)

func TestNoDirectCarrierBurnsWithNowhereToGo(t *testing.T) {
	dst := NewPeerPool([]string{"only"}, 0, filepath.Join(t.TempDir(), "d.json"))
	b := &TCP{isClient: true}
	b.SetPeerPool(dst)
	for i := 0; i < 5; i++ {
		tcpWalk(b)
	}
	if got := burnedIn(dst); len(got) > 0 {
		t.Fatalf("the only destination was condemned (%v) though nothing varied and there is nowhere "+
			"to rotate to", got)
	}
}
