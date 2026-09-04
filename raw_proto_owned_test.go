package main

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

func bareWith(proto int) *Config {
	c := validRaw()
	c.RawProfile, c.RawProto = "bare", proto
	return c
}

func protoOf(t *testing.T, name string) int {
	t.Helper()
	for n := 1; n <= 255; n++ {
		if owner, ok := packet.RawProfileOwning(n); ok && owner == name {
			return n
		}
	}
	t.Fatalf("profile %q owns no protocol number in 1..255", name)
	return 0
}

func TestBareRefusesAProtocolNumberAnotherProfileOwns(t *testing.T) {
	for _, name := range packet.RawProfileNames() {
		n := protoOf(t, name)
		err := bareWith(n).validate()
		if name == "bare" {
			if err != nil {
				t.Errorf("bare must accept its own protocol number %d, got %v", n, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("bare + raw_proto %d (owned by %q) must be refused: it sends the number with no header", n, name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error for raw_proto %d must name the %q profile to use instead, got: %v", n, name, err)
		}
	}

	for _, free := range []int{2, 143, 200, 252, 254} {
		if _, taken := packet.RawProfileOwning(free); taken {
			continue
		}
		if err := bareWith(free).validate(); err != nil {
			t.Errorf("bare + raw_proto %d owns no header and must be allowed, got %v", free, err)
		}
	}

	c := validRaw()
	c.RawProfile, c.RawProto = "tcp", 200
	if err := c.validate(); err == nil {
		t.Error("a non-bare profile must still refuse raw_proto outright — its number is tied to its header")
	}
}
