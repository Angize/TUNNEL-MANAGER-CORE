package packet

import (
	"bytes"
	"net"
	"testing"
)

// TestRawChecksumBindsSourceMatchesTheEncapsulation derives the answer from rawEncap instead of
// restating a list: for every profile it builds the same frame twice, changing ONLY the source, and
// requires rawChecksumBindsSource to agree with whether the bytes actually differ. That is the property
// sendViaConn's fallback turns on, so a new profile whose header binds the source fails here.
func TestRawChecksumBindsSourceMatchesTheEncapsulation(t *testing.T) {
	body := []byte("a sealed core frame, long enough to checksum meaningfully 0123456789")
	dst := net.IPv4(198, 51, 100, 20)
	srcA := net.IPv4(203, 0, 113, 1)
	srcB := net.IPv4(203, 0, 113, 2)

	for profile := range rawProfiles {
		for _, isClient := range []bool{true, false} {
			a := rawEncap(profile, body, srcA, dst, isClient, 0xBEEF, 0, 0, 7, 9, 0x11223344)
			b := rawEncap(profile, body, srcB, dst, isClient, 0xBEEF, 0, 0, 7, 9, 0x11223344)
			differs := !bytes.Equal(a, b)
			if want := rawChecksumBindsSource(profile); differs != want {
				t.Fatalf("raw/%s (isClient=%v): the encapsulation %s the source, but rawChecksumBindsSource says %v — sendViaConn's fallback decides on this",
					profile, isClient, map[bool]string{true: "DEPENDS on", false: "is independent of"}[differs], want)
			}
		}
	}
}

// TestRawChecksumBindsSourceCoversEveryProfile: the switch keys off the protocol number, so a profile
// name it does not know silently answers "independent" — the answer that lets a packet out. The two
// lists below must between them name EVERY key of rawProfiles, so a newly registered profile fails this
// test until someone states which side it is on. The silent default is the dangerous answer.
func TestRawChecksumBindsSourceCoversEveryProfile(t *testing.T) {
	bindsSource := []string{"udp", "tcp"} // L4 checksum folds in the IPv4 pseudo-header
	// bytes do not depend on the source: none of these carries a checksum at all
	independent := []string{"bare", "ipip", "gre", "icmp", "esp", "ah", "etherip", "ipcomp", "l2tpv3"}

	classified := map[string]bool{}
	for _, p := range bindsSource {
		classified[p] = true
	}
	for _, p := range independent {
		classified[p] = true
	}
	for profile := range rawProfiles {
		if !classified[profile] {
			t.Fatalf("raw/%s is registered in rawProfiles and this test does not say whether its "+
				"encapsulation binds the source. rawChecksumBindsSource keys off the protocol number, so a "+
				"name it does not recognise silently answers \"independent\" — the answer that lets a "+
				"wrong-checksum packet onto the wire from sendViaConn's degraded send", profile)
		}
	}
	for p := range classified {
		if _, ok := rawProfiles[p]; !ok {
			t.Fatalf("this test classifies raw/%s, which is no longer a registered profile — the lists "+
				"above have drifted from rawProfiles and can no longer prove they cover it", p)
		}
	}

	if rawChecksumBindsSource("not-a-profile") {
		t.Fatal("an unknown profile must not be treated as source-bound")
	}
	for _, p := range bindsSource {
		if !rawChecksumBindsSource(p) {
			t.Fatalf("raw/%s carries an L4 checksum over the pseudo-header, so its bytes are only valid "+
				"from the source they were built for", p)
		}
	}
	for _, p := range independent {
		if rawChecksumBindsSource(p) {
			t.Fatalf("raw/%s does not checksum the source — dropping its degraded send would lose a valid packet", p)
		}
	}
}
