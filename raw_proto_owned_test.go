package main

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

// bareWith returns a valid raw client config on the bare profile with a custom outer protocol number.
func bareWith(proto int) *Config {
	c := validRaw()
	c.RawProfile, c.RawProto = "bare", proto
	return c
}

// protoOf reads a profile's protocol number back out of the packet package, so this test carries no
// literal table of its own to drift.
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

// TestBareRefusesAProtocolNumberAnotherProfileOwns closes the shape that reaches the operator as packet
// loss and nothing else. bare writes NO L4 header, so raw_proto 6 puts ciphertext where a middlebox
// expects a TCP header: a different random port pair every packet, no SYN it ever saw, a checksum that
// cannot verify. The flow is dropped in the path, far from whoever set the number. Every such number
// already HAS a profile that forges the header too, so the config is refused with that profile named.
//
// Driven off the profile table rather than a literal list, so a newly registered profile is covered the
// day it lands instead of the day someone remembers this test.
func TestBareRefusesAProtocolNumberAnotherProfileOwns(t *testing.T) {
	for _, name := range packet.RawProfileNames() {
		n := protoOf(t, name)
		err := bareWith(n).validate()
		if name == "bare" { // its own native number is not a borrowed one
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

	// A number no profile owns is the whole point of the knob and must still pass. Skipped if a later
	// profile claims one, which is the only way this list can go stale.
	for _, free := range []int{2, 143, 200, 252, 254} {
		if _, taken := packet.RawProfileOwning(free); taken {
			continue
		}
		if err := bareWith(free).validate(); err != nil {
			t.Errorf("bare + raw_proto %d owns no header and must be allowed, got %v", free, err)
		}
	}

	// The rule stays bare-only: another profile may not override its number at all, free or not. That is
	// a pre-existing rule, pinned here so the new branch cannot swallow it.
	c := validRaw()
	c.RawProfile, c.RawProto = "tcp", 200
	if err := c.validate(); err == nil {
		t.Error("a non-bare profile must still refuse raw_proto outright — its number is tied to its header")
	}

	// The SPOOF carrier is headerless in exactly the same way and takes the same knob, so it takes the
	// same rule. Left out, the number the operator could not set on bare is still settable one tab away.
	sp := validSpoof()
	sp.RawProto = protoOf(t, "tcp")
	if err := sp.validate(); err == nil {
		t.Error("spoof is bare-like and headerless — it must refuse a borrowed protocol number too")
	}
	sp.RawProto = 200
	if _, taken := packet.RawProfileOwning(200); !taken {
		if err := sp.validate(); err != nil {
			t.Errorf("spoof must still accept a free protocol number, got %v", err)
		}
	}
}
