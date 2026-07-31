//go:build linux

package packet

import (
	"errors"
	"net"
	"testing"
)

// TestSetDesyncKeepsTheModesThatNeedNoHdrincl pins which decoy modes survive a host where the
// IP_HDRINCL socket cannot open (a container without CAP_NET_RAW for AF_INET/SOCK_RAW, a seccomp
// profile, a hardened kernel).
//
// The two decoy kinds use two DIFFERENT sockets for opposite reasons: a low-TTL decoy needs
// IP_HDRINCL so the kernel honours the forged TTL, while a bad-checksum decoy must AVOID IP_HDRINCL
// because it always repairs the checksum, and goes out over AF_PACKET instead. SetDesync opened the
// IP_HDRINCL socket before it looked at the mode and returned on failure, so an operator who chose
// mode=badsum — which never touches that socket — lost the whole camouflage and read
// "fake-desync disabled" in the journal with no hint that their mode did not need it.
//
// The matrix is over the mode, because the mode is what decides which sockets are needed. It drives
// the real SetDesync and then asserts what sendFakes will actually do, not just the stored config.
func TestSetDesyncKeepsTheModesThatNeedNoHdrincl(t *testing.T) {
	boom := errors.New("operation not permitted")
	for _, tc := range []struct {
		mode      string
		stillOn   bool // desync survives a failed IP_HDRINCL open
		wantOpen  bool // ...and whether it even tried to open one
		decoysOut int  // decoys that still reach a socket, out of 2
	}{
		{"badsum", true, false, 2}, // every decoy is AF_PACKET: the socket is irrelevant
		{"both", true, true, 1},    // the badsum half survives, the low-TTL half does not
		{"ttl", false, true, 0},    // nothing left — this is the only mode that is really off
	} {
		t.Run(tc.mode, func(t *testing.T) {
			// A resolver that always fails never caches (TestL2InjectResolvesPerDestination pins
			// that), so its call count is an exact count of the sendTo calls the decoy path made —
			// which a succeeding resolver would hide behind l2inject's per-destination cache. A cold
			// neighbour is also what this really looks like in production.
			f := &fakeResolver{err: errors.New("l2: neighbour not resolved")}
			tried := false
			r := &Raw{isClient: true, proto: protoBIP, profile: "bip", fakeFd: -1}
			r.link = &directLink{r: r}
			r.localIP.Store(&net.IPAddr{IP: net.IPv4(192, 0, 2, 1)})
			r.openFakeFd = func(int) (int, error) { tried = true; return -1, boom }

			r.SetDesync(true, 4, 2, tc.mode)

			if tried != tc.wantOpen {
				t.Fatalf("mode=%s: tried to open an IP_HDRINCL socket = %v, want %v — %q emits no low-TTL decoy, so opening one is pure cost and its failure must not be fatal",
					tc.mode, tried, tc.wantOpen, tc.mode)
			}
			if r.desync.on != tc.stillOn {
				t.Fatalf("mode=%s: desync.on = %v after a failed IP_HDRINCL open, want %v",
					tc.mode, r.desync.on, tc.stillOn)
			}
			if r.fakeFd != -1 {
				t.Fatalf("mode=%s: fakeFd = %d after a failed open, want -1", tc.mode, r.fakeFd)
			}

			// What actually reaches the send path. The injector is stubbed AFTER SetDesync so this
			// counts decoys the path really hands to a socket, independent of whether AF_PACKET
			// opened on this box.
			r.inj = testInjector(f)
			peer := &net.IPAddr{IP: net.IPv4(203, 0, 113, 5)}
			r.peer.Store(peer)
			r.sendFakes(peer)
			if got := len(f.asked()); got != tc.decoysOut {
				t.Fatalf("mode=%s: %d decoys reached a socket, want %d — the modes that do not need the IP_HDRINCL socket must be delivered in full",
					tc.mode, got, tc.decoysOut)
			}
		})
	}
}
