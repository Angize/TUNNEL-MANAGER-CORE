package main

import (
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

type pinsByBind struct{ got string }

func (p *pinsByBind) SetSourceIP(ip string) { p.got = ip }

type pinsByPool struct{ got *packet.PeerPool }

func (p *pinsByPool) SetSourcePool(sp *packet.PeerPool) { p.got = sp }

type pinsNothing struct{}

func TestBindIPReachesEveryCarrierThatCanHonourIt(t *testing.T) {
	const ip = "203.0.113.9"

	t.Run("tcp family binds directly", func(t *testing.T) {
		c := &pinsByBind{}
		if got := pinSource(c, &Config{Role: "client", BindIP: ip, Transport: "tcp"}); got != pinByBind {
			t.Fatalf("pinSource = %q, want %q", got, pinByBind)
		}
		if c.got != ip {
			t.Errorf("SetSourceIP got %q, want %q", c.got, ip)
		}
	})

	t.Run("datagram carriers pin through a one-entry pool", func(t *testing.T) {
		c := &pinsByPool{}
		if got := pinSource(c, &Config{Role: "client", BindIP: ip, Transport: "raw"}); got != pinByPool {
			t.Fatalf("pinSource = %q, want %q — bind_ip must not be dropped on a carrier that can pin a source", got, pinByPool)
		}
		if c.got == nil {
			t.Fatal("no source pool was installed, so the kernel still chooses the source")
		}

	})

	t.Run("an explicit src_ips pool supersedes it", func(t *testing.T) {
		c := &pinsByPool{}
		cfg := &Config{Role: "client", BindIP: ip, Transport: "udp", SrcIPs: []string{"198.51.100.4", "198.51.100.5"}}
		if got := pinSource(c, cfg); got != pinBySrcIPs {
			t.Fatalf("pinSource = %q, want %q", got, pinBySrcIPs)
		}
		if c.got != nil {
			t.Error("bind_ip installed a pool over the operator's src_ips — the field doc says src_ips wins")
		}
	})

	t.Run("a carrier that can pin nothing says so", func(t *testing.T) {
		if got := pinSource(&pinsNothing{}, &Config{Role: "client", BindIP: ip, Transport: "dns"}); got != pinUnsupported {
			t.Fatalf("pinSource = %q, want %q — silence here is what made this a no-op nobody could see", got, pinUnsupported)
		}
	})

	t.Run("server role and an empty bind_ip do nothing", func(t *testing.T) {
		c := &pinsByBind{}
		if got := pinSource(c, &Config{Role: "server", BindIP: ip}); got != pinNone {
			t.Errorf("server: pinSource = %q, want %q", got, pinNone)
		}
		if got := pinSource(c, &Config{Role: "client"}); got != pinNone {
			t.Errorf("no bind_ip: pinSource = %q, want %q", got, pinNone)
		}
		if c.got != "" {
			t.Errorf("a source was pinned when none was asked for: %q", c.got)
		}
	})
}
