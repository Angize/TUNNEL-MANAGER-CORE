//go:build linux

package packet

import (
	"net"
	"strconv"
	"testing"
)

func TestFluxDropRulesMatchOnlyItsOwnUDPPorts(t *testing.T) {
	peer := net.ParseIP("203.0.113.9")
	for _, c := range []struct {
		carrier string
		ports   []uint16
	}{{"udp", fluxDportPool}, {"stun", fluxStunDports}, {"", fluxDportPool}} {
		got := fluxDropMatches(peer, c.carrier)
		if len(got) != len(c.ports) {
			t.Fatalf("carrier %q: %d rules for %d pool ports: %v", c.carrier, len(got), len(c.ports), got)
		}
		seen := map[string]bool{}
		for _, m := range got {
			if len(m) != 6 || m[0] != "-s" || m[1] != peer.String() || m[2] != "-p" || m[3] != "udp" || m[4] != "--dport" {
				t.Fatalf("carrier %q: a rule is not source-scoped UDP-with-a-dport: %v", c.carrier, m)
			}
			seen[m[5]] = true
		}
		for _, p := range c.ports {
			if !seen[strconv.Itoa(int(p))] {
				t.Fatalf("carrier %q: no rule covers pool port %d: %v", c.carrier, p, got)
			}
		}
	}
}

func TestFluxPortPoolsCannotCollideWithATunnelPort(t *testing.T) {
	for name, pool := range map[string][]uint16{"udp": fluxDportPool, "stun": fluxStunDports} {
		if len(pool) == 0 {
			t.Fatalf("the %s pool is empty — addFluxDrop would install nothing", name)
		}
		for _, p := range pool {
			switch {
			case p == 53:
				t.Fatalf("%s pool: port %d is the fixed dns-transport port", name, p)
			case p == 4789:
				t.Fatalf("%s pool: port %d is the vxlan default port", name, p)
			case p >= 20001 && p <= 20255:
				t.Fatalf("%s pool: port %d is inside the tunnel port range (20000+id, id 1..255)", name, p)
			}
		}
	}
}
