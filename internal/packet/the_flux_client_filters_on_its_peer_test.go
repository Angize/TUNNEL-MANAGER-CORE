//go:build linux

package packet

import (
	"net"
	"testing"
)

// The flux receive socket filtered only on "IP protocol == UDP", so the kernel copied every UDP packet on
// the box into the one goroutine that also runs flux's crypto -- other tunnels' carrier traffic, every tun
// device's inner UDP, DNS, the lot. The client knows exactly one peer and its address never moves (flux
// rotates PORTS per epoch, not the peer IP), so the client now filters on the peer's source address in the
// kernel and the copy never happens. The server still accepts any source: its clients roam, and the
// per-epoch destination-port set it already checks in userspace is the only thing it can bind to.
func TestTheFluxClientFiltersOnItsPeer(t *testing.T) {
	const peer, other = "203.0.113.7", "203.0.113.8"
	prog := bpfIPProtoSrc(protoUDP, net.ParseIP(peer))
	for _, tc := range []struct {
		name string
		pkt  []byte
		keep bool
	}{
		{"a carrier frame from the peer", ip4(protoUDP, peer, "10.0.0.1"), true},
		{"udp from any other host", ip4(protoUDP, other, "10.0.0.1"), false},
		{"the peer's tcp, not our carrier", ip4(6, peer, "10.0.0.1"), false},
		{"an icmp echo from the peer", ip4(1, peer, "10.0.0.1"), false},
	} {
		if got := runBPF(t, prog, tc.pkt) > 0; got != tc.keep {
			t.Errorf("%s: kept=%v, want %v", tc.name, got, tc.keep)
		}
	}

	// with no peer to pin (the server), the filter must fall back to keeping every UDP frame
	broad := bpfIPProtoSrc(protoUDP, nil)
	if runBPF(t, broad, ip4(protoUDP, other, "10.0.0.1")) == 0 {
		t.Error("the server's fallback filter dropped a UDP frame it needs to inspect")
	}
}
