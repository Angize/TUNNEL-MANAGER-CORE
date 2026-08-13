//go:build linux

package packet

import (
	"math/rand"
	"net"
	"testing"
)

// refSumBytes is RFC 1071 written the obvious way, one 16-bit word at a time. The fast version has to
// agree with it for every length, including the odd tail and the empty buffer — a checksum that is
// wrong by one word puts a bad-checksum "TCP" or "UDP" segment on the wire on EVERY packet, which our
// own receiver would not notice and a stateful middlebox would drop.
func refSumBytes(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func TestSumBytesAgreesWithTheObviousLoop(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for n := 0; n <= 300; n++ {
		b := make([]byte, n)
		rng.Read(b)
		if got, want := sumBytes(b), refSumBytes(b); got != want {
			t.Fatalf("len %d: sumBytes = %d, want %d", n, got, want)
		}
	}
	// ...and at MTU-ish sizes, where the wide read does most of the work, with the byte patterns that
	// break a sloppy shift: all-ones and alternating.
	for _, fill := range []byte{0x00, 0xff, 0xaa} {
		for _, n := range []int{1400, 1401, 1500, 9000} {
			b := make([]byte, n)
			for i := range b {
				b[i] = fill
			}
			if got, want := sumBytes(b), refSumBytes(b); got != want {
				t.Fatalf("len %d fill %#x: sumBytes = %d, want %d", n, fill, got, want)
			}
		}
	}
	// The whole point: no allocation, since it runs over every byte of every udp/tcp-profile packet.
	b := make([]byte, 1400)
	if n := testing.AllocsPerRun(100, func() { _ = sumBytes(b) }); n != 0 {
		t.Errorf("%v allocation(s) per checksum pass", n)
	}
}

// The pinned-source control message is 32 bytes of identical work on every outbound packet of a
// pooled client or a pool server. It changes only when the source does.
func TestThePinnedSourceControlMessageIsBuiltOnce(t *testing.T) {
	r := &Raw{}
	src := net.IPv4(10, 20, 0, 5)

	first := r.srcOOB(src)
	if want := pktinfoOOB(src); string(first) != string(want) {
		t.Fatalf("the cached control message is not what pktinfoOOB builds:\n got %v\nwant %v", first, want)
	}
	if n := testing.AllocsPerRun(200, func() { _ = r.srcOOB(src) }); n != 0 {
		t.Errorf("%v allocation(s) per outbound packet for a source that has not changed", n)
	}

	// A rotation to another source must be picked up, not served from the cache.
	other := net.IPv4(10, 20, 0, 9)
	got := r.srcOOB(other)
	if string(got) == string(first) {
		t.Fatal("the control message did not follow the source; every packet would leave from the old one")
	}
	if want := pktinfoOOB(other); string(got) != string(want) {
		t.Errorf("after the rotation the cached message is wrong:\n got %v\nwant %v", got, want)
	}
	if string(r.srcOOB(src)) != string(first) {
		t.Error("rotating back produced a different control message for the same source")
	}
}
