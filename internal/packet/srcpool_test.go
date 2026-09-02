package packet

import (
	"net"
	"testing"
)

func TestServerSrcAllowed(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }

	r := &Raw{isClient: false}
	r.SetPeerSources([]string{"10.0.0.5", "10.0.0.7"})
	if !r.srcAllowed(ip("10.0.0.5")) || !r.srcAllowed(ip("10.0.0.7")) {
		t.Error("raw: pool sources must be admitted")
	}
	if r.srcAllowed(ip("10.0.0.9")) {
		t.Error("raw: unrelated host must NOT be admitted")
	}
	r0 := &Raw{isClient: false}
	if r0.srcAllowed(ip("10.0.0.5")) {
		t.Error("raw non-pool server must not admit extra sources")
	}
}
