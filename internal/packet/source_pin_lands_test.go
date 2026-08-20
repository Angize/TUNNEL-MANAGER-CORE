//go:build linux

package packet

import (
	"testing"
)

func TestASourcePinLandsWhenTheSourceIsAdopted(t *testing.T) {
	const other = "127.0.0.2"

	t.Run("udp", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, 0)
		b := &UDP{isClient: true}
		b.SetSourcePool(sp)
		if !sp.selectEntry(other) || !sp.isPinned() {
			t.Fatal("the pin did not take — the rest of this case would be vacuous")
		}
		b.adoptSourceUDP()
		if sp.isPinned() {
			t.Error("the jump is still in progress after the socket really rebound onto the pinned source: rotation stays frozen for the whole pinTTL and the panel shows a move that already completed")
		}
	})

	t.Run("raw", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, 0)
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if !sp.selectEntry(other) || !sp.isPinned() {
			t.Fatal("the pin did not take")
		}
		r.adoptSourceRaw()
		if sp.isPinned() {
			t.Error("a raw source pin is still in progress after the source was adopted")
		}
	})

	t.Run("flux", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, 0)
		f := &Flux{isClient: true}
		f.SetSourcePool(sp)
		if !sp.selectEntry(other) || !sp.isPinned() {
			t.Fatal("the pin did not take")
		}
		f.adoptSourceFlux()
		if sp.isPinned() {
			t.Error("a flux source pin is still in progress after the source was adopted")
		}
	})

	t.Run("a destination success does not release a source pin", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, 0)
		dp := NewPeerPool([]string{"203.0.113.10", "203.0.113.11"}, 0)
		rc := &rotationController{dst: dp, src: sp}
		if !sp.selectEntry(other) || !sp.isPinned() {
			t.Fatal("the pin did not take")
		}
		rc.success()
		if !sp.isPinned() {
			t.Error("a destination handshake released the SOURCE pin: the panel reports the jump complete while the tunnel still egresses from the old address")
		}
	})
}
