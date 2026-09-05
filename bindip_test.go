package main

import (
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

type bindsDirectly struct{ got string }

func (p *bindsDirectly) SetSourceIP(ip string) { p.got = ip }

type bindsViaPool struct{ got *packet.PeerPool }

func (p *bindsViaPool) SetSourcePool(sp *packet.PeerPool) { p.got = sp }

type bindsNothing struct{}

func TestBindIPReachesEveryCarrierThatCanHonourIt(t *testing.T) {
	const ip = "203.0.113.9"

	t.Run("tcp family binds directly", func(t *testing.T) {
		c := &bindsDirectly{}
		if got := sourceMode(c, &Config{Role: "client", BindIP: ip, Transport: "tcp"}); got != srcByBind {
			t.Fatalf("sourceMode = %q, want %q", got, srcByBind)
		}
		if c.got != ip {
			t.Errorf("SetSourceIP got %q, want %q", c.got, ip)
		}
	})

	t.Run("datagram carriers fix the source through a one-entry pool", func(t *testing.T) {
		c := &bindsViaPool{}
		if got := sourceMode(c, &Config{Role: "client", BindIP: ip, Transport: "raw"}); got != srcByPool {
			t.Fatalf("sourceMode = %q, want %q — bind_ip must not be dropped on a carrier that can fix a source", got, srcByPool)
		}
		if c.got == nil {
			t.Fatal("no source pool was installed, so the kernel still chooses the source")
		}

	})

	t.Run("an explicit src_ips pool supersedes it", func(t *testing.T) {
		c := &bindsViaPool{}
		cfg := &Config{Role: "client", BindIP: ip, Transport: "udp", SrcIPs: []string{"198.51.100.4", "198.51.100.5"}}
		if got := sourceMode(c, cfg); got != srcBySrcIPs {
			t.Fatalf("sourceMode = %q, want %q", got, srcBySrcIPs)
		}
		if c.got != nil {
			t.Error("bind_ip installed a pool over the operator's src_ips — the field doc says src_ips wins")
		}
	})

	t.Run("a carrier that can fix nothing says so", func(t *testing.T) {
		if got := sourceMode(&bindsNothing{}, &Config{Role: "client", BindIP: ip, Transport: "dns"}); got != srcUnsupported {
			t.Fatalf("sourceMode = %q, want %q — silence here is what made this a no-op nobody could see", got, srcUnsupported)
		}
	})

	t.Run("server role and an empty bind_ip do nothing", func(t *testing.T) {
		c := &bindsDirectly{}
		if got := sourceMode(c, &Config{Role: "server", BindIP: ip}); got != srcNone {
			t.Errorf("server: sourceMode = %q, want %q", got, srcNone)
		}
		if got := sourceMode(c, &Config{Role: "client"}); got != srcNone {
			t.Errorf("no bind_ip: sourceMode = %q, want %q", got, srcNone)
		}
		if c.got != "" {
			t.Errorf("a source was bound when none was asked for: %q", c.got)
		}
	})
}
