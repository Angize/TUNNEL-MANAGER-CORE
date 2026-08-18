//go:build linux

package packet

import (
	"net"
	"testing"
)

func TestOneEntrySourcePoolPinsTheSource(t *testing.T) {

	const pin = "127.0.0.1"

	t.Run("raw stamps the crafted header from it", func(t *testing.T) {
		r := &Raw{isClient: true, proto: protoBare, profile: "bare", fakeFd: -1}
		r.link = &directLink{r: r}
		r.SetSourcePool(NewPeerPool([]string{pin}, 0, ""))
		if got := r.srcIP(); got == nil || got.String() != pin {
			t.Fatalf("raw source = %v, want %s — the crafted IPv4 header would carry the kernel's choice", got, pin)
		}
	})

	t.Run("flux stamps the crafted header from it", func(t *testing.T) {
		f := &Flux{isClient: true}
		f.SetSourcePool(NewPeerPool([]string{pin}, 0, ""))
		if got := f.srcIP(); got == nil || got.String() != pin {
			t.Fatalf("flux source = %v, want %s", got, pin)
		}
	})

	t.Run("udp binds its socket to it", func(t *testing.T) {
		b := &UDP{isClient: true}
		b.SetSourcePool(NewPeerPool([]string{pin}, 0, ""))
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

	t.Run("it never moves", func(t *testing.T) {
		p := NewPeerPool([]string{pin}, 0, "")
		if addr, moved := p.nextEndpoint(true); moved {
			t.Fatalf("a one-entry pool rotated to %q; a pinned source must stay put", addr)
		}
	})
}
