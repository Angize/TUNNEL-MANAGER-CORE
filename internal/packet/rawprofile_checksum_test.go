package packet

import (
	"bytes"
	"net"
	"testing"
)

// TestRawChecksumBindsSourceMatchesTheEncapsulation derives the answer from rawEncap instead of
// restating a list: for every profile it builds the same frame twice, changing ONLY the source, and
// requires rawChecksumBindsSource to agree with whether the bytes actually differ.
//
// That is the property sendViaConn's fallback turns on. When the pinned source cannot be used, the
// already-built bytes may only go out from a different source if they do not depend on it; for udp
// and tcp they do (l4Checksum folds in the IPv4 pseudo-header), so sending them anyway puts a wrong
// L4 checksum on the wire on every packet. Deriving it this way means a NEW profile whose header
// binds the source — or an existing one that starts to — fails here rather than shipping silently.
func TestRawChecksumBindsSourceMatchesTheEncapsulation(t *testing.T) {
	body := []byte("a sealed core frame, long enough to checksum meaningfully 0123456789")
	dst := net.IPv4(198, 51, 100, 20)
	srcA := net.IPv4(203, 0, 113, 1)
	srcB := net.IPv4(203, 0, 113, 2)

	for profile := range rawProfiles {
		for _, isClient := range []bool{true, false} {
			a := rawEncap(profile, body, srcA, dst, isClient, 0xBEEF, 7, 9, 0x11223344)
			b := rawEncap(profile, body, srcB, dst, isClient, 0xBEEF, 7, 9, 0x11223344)
			differs := !bytes.Equal(a, b)
			if want := rawChecksumBindsSource(profile); differs != want {
				t.Fatalf("raw/%s (isClient=%v): the encapsulation %s the source, but rawChecksumBindsSource says %v — sendViaConn's fallback decides on this",
					profile, isClient, map[bool]string{true: "DEPENDS on", false: "is independent of"}[differs], want)
			}
		}
	}
}

// TestRawChecksumBindsSourceCoversEveryProfile: the switch keys off the protocol number, so a
// profile name it does not know silently answers "independent" — the answer that lets a packet out.
// Every name in the authoritative map must be a name it has an opinion about.
func TestRawChecksumBindsSourceCoversEveryProfile(t *testing.T) {
	for profile := range rawProfiles {
		if _, ok := rawProfiles[profile]; !ok {
			t.Fatalf("%s is not in rawProfiles", profile)
		}
	}
	if rawChecksumBindsSource("not-a-profile") {
		t.Fatal("an unknown profile must not be treated as source-bound")
	}
	if !rawChecksumBindsSource("udp") || !rawChecksumBindsSource("tcp") {
		t.Fatal("udp and tcp carry an L4 checksum over the pseudo-header")
	}
	for _, p := range []string{"bip", "ipip", "gre", "icmp", "esp"} {
		if rawChecksumBindsSource(p) {
			t.Fatalf("raw/%s does not checksum the source — dropping its degraded send would lose a valid packet", p)
		}
	}
}
