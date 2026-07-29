//go:build linux

package packet

import (
	"net"
	"testing"
)

// The carrier half of the bind_ip chain (main.pinSource is the other): a ONE-ENTRY source pool must
// actually pin the source, on every carrier that has no separate bind. This is what lets bind_ip be
// honoured on udp/raw/flux at all — the pool's gate is len>=1 precisely so a lone entry is a fixed
// source. If any of these stopped seeding from the pool, bind_ip would go back to being a silent
// no-op there and the kernel would pick the route's default source again.
func TestOneEntrySourcePoolPinsTheSource(t *testing.T) {
	// A loopback address, so udp's real bind can succeed on any host.
	const pin = "127.0.0.1"

	t.Run("raw stamps the crafted header from it", func(t *testing.T) {
		r := &Raw{isClient: true, proto: protoBIP, profile: "bip", fakeFd: -1}
		r.link = &directLink{r: r}
		r.SetSourcePool(NewPeerPool([]string{pin}, false, 0, ""))
		if got := r.srcIP(); got == nil || got.String() != pin {
			t.Fatalf("raw source = %v, want %s — the crafted IPv4 header would carry the kernel's choice", got, pin)
		}
	})

	t.Run("flux stamps the crafted header from it", func(t *testing.T) {
		f := &Flux{isClient: true}
		f.SetSourcePool(NewPeerPool([]string{pin}, false, 0, ""))
		if got := f.srcIP(); got == nil || got.String() != pin {
			t.Fatalf("flux source = %v, want %s", got, pin)
		}
	})

	t.Run("udp binds its socket to it", func(t *testing.T) {
		b := &UDP{isClient: true}
		b.SetSourcePool(NewPeerPool([]string{pin}, false, 0, ""))
		c := b.conn.Load()
		if c == nil {
			t.Fatal("udp bound no socket, so it still egresses from the kernel's default source")
		}
		t.Cleanup(func() { c.Close() })
		la, ok := c.LocalAddr().(*net.UDPAddr)
		if !ok || la.IP.String() != pin {
			t.Fatalf("udp bound to %v, want %s", c.LocalAddr(), pin)
		}
	})

	// A fixed source must never be burned or rotated away: it is the only entry, so burning it would
	// leave the pool with nothing and a rotation has nowhere to go. main.pinSource builds it with
	// auto-burn off and rotate 0 for exactly this reason.
	t.Run("it never moves", func(t *testing.T) {
		p := NewPeerPool([]string{pin}, false, 0, "")
		if addr, moved := p.nextEndpoint(true); moved {
			t.Fatalf("a one-entry pool rotated to %q; a pinned source must stay put", addr)
		}
	})
}
