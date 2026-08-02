package main

import (
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

// pinsByBind is a tcp/ws/http-shaped carrier: it pins a source itself.
type pinsByBind struct{ got string }

func (p *pinsByBind) SetSourceIP(ip string) { p.got = ip }

// pinsByPool is a udp/raw/flux-shaped carrier: no separate bind, only a source pool.
type pinsByPool struct{ got *packet.PeerPool }

func (p *pinsByPool) SetSourcePool(sp *packet.PeerPool) { p.got = sp }

// pinsNothing is a dns-shaped carrier: it can pin no source at all.
type pinsNothing struct{}

// bind_ip must reach EVERY carrier that can honour it. It was implemented only for the TCP family: the
// type assertion had no else and the "binding outbound source IP" log line lived inside its successful
// branch, so on udp/raw/flux the knob was a silent no-op while the panel showed the node's registered
// address. The node stamps bind_ip from local_ip on every client core tunnel.
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
		// That a one-entry pool really pins the source on udp/raw/flux is the carrier's half of the
		// chain: packet.TestOneEntrySourcePoolPinsTheSource.
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

	t.Run("a forged source supersedes it", func(t *testing.T) {
		c := &pinsByPool{}
		cfg := &Config{Role: "client", BindIP: ip, Transport: "spoof", SpoofSrc: "192.0.2.7"}
		if got := pinSource(c, cfg); got != pinBySpoof {
			t.Fatalf("pinSource = %q, want %q", got, pinBySpoof)
		}
		if c.got != nil {
			t.Error("a pool was installed under spoof_src; the carrier refuses it and blames a pool the operator never configured")
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
