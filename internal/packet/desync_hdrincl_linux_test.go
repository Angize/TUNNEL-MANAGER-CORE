//go:build linux

package packet

import (
	"errors"
	"net"
	"testing"
)

func TestSetDesyncKeepsTheModesThatNeedNoHdrincl(t *testing.T) {
	boom := errors.New("operation not permitted")
	for _, tc := range []struct {
		mode      string
		stillOn   bool
		wantOpen  bool
		decoysOut int
	}{
		{"badsum", true, false, 2},
		{"both", true, true, 1},
		{"ttl", false, true, 0},
	} {
		t.Run(tc.mode, func(t *testing.T) {

			f := &fakeResolver{err: errors.New("l2: neighbour not resolved")}
			tried := false
			r := &Raw{isClient: true, proto: protoBare, profile: "bare", fakeFd: -1}
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
