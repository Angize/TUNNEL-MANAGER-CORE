//go:build linux

package packet

import (
	"testing"
)

// A SOURCE pin lands when the source is adopted — there is no handshake to read it off.
//
// A pin is «این را فعال کن»: a momentary jump that releases itself the instant it arrives. For a
// DESTINATION pin the release signal is obvious — the carrier re-handshakes onto the new endpoint, so
// "we connected" and "we connected on the pin" are the same statement, and pinLanded() reads it off
// the success path.
//
// A SOURCE swap is not like that, and pinLanded's doc claimed it was ("udp/raw/flux all re-point at
// current() in their adopt path and then re-handshake"). The source is independent of the AEAD keys —
// keeping the session across the swap is the whole point — so nothing re-handshakes, and the success
// path that would have released the pin only runs when something failed first
// (`if b.peerAnswered.Load() && (failN > 0 || ...)`). On a healthy tunnel it never runs at all.
//
// So the operator's jump sat "in progress" for the entire pinTTL: rotation frozen, the panel showing a
// move that had in fact completed a second after the button was pressed.
func TestASourcePinLandsWhenTheSourceIsAdopted(t *testing.T) {
	const other = "127.0.0.2"

	t.Run("udp", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, true, 0, "")
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
		sp := NewPeerPool([]string{usableLoopbackIP, other}, true, 0, "")
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
		sp := NewPeerPool([]string{usableLoopbackIP, other}, true, 0, "")
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

	// ...and the other half of the contract: a DESTINATION handshake must NOT release a source pin.
	// It says nothing about the source, and releasing on it would report the operator's jump as
	// complete over a tunnel still egressing from the old address — which is what success() did.
	t.Run("a destination success does not release a source pin", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, other}, true, 0, "")
		dp := NewPeerPool([]string{"203.0.113.10", "203.0.113.11"}, true, 0, "")
		rc := &rotationController{dst: dp, src: sp}
		if !sp.selectEntry(other) || !sp.isPinned() {
			t.Fatal("the pin did not take")
		}
		rc.success() // the DESTINATION carrier handshook; nothing happened to the source
		if !sp.isPinned() {
			t.Error("a destination handshake released the SOURCE pin: the panel reports the jump complete while the tunnel still egresses from the old address")
		}
	})
}
