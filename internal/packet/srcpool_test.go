package packet

import (
	"net"
	"testing"
)

func TestServerSrcAllowed(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }

	f := &Flux{isClient: false}
	f.SetPeerSources([]string{"10.0.0.5", "10.0.0.6:0", "10.0.0.7"})
	for _, in := range []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"} {
		if !f.srcAllowed(ip(in)) {
			t.Errorf("flux: expected %s admitted", in)
		}
	}
	if f.srcAllowed(ip("10.0.0.9")) {
		t.Error("flux: unrelated host 10.0.0.9 must NOT be admitted")
	}

	fc := &Flux{isClient: true}
	fc.SetPeerSources([]string{"10.0.0.5"})
	if fc.srcAllowed(ip("10.0.0.5")) {
		t.Error("flux client must ignore SetPeerSources")
	}

	f0 := &Flux{isClient: false}
	if f0.srcAllowed(ip("10.0.0.5")) {
		t.Error("flux non-pool server must not admit extra sources")
	}

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
