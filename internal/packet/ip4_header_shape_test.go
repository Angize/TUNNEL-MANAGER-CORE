//go:build linux

package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestCraftedHeadersLookLikeTheFlowTheyJoin(t *testing.T) {
	src, dst := net.IPv4(10, 99, 0, 1), net.IPv4(10, 99, 0, 2)
	body := []byte("a sealed core frame")

	seen := map[uint16]bool{}
	for i := 0; i < 64; i++ {
		for _, tc := range []struct {
			name string
			pkt  []byte
		}{
			{"buildIP4 (flux + spoof REAL data)", buildIP4(src, dst, protoBare, body)},
			{"low-TTL decoy", buildIP4Ext(src, dst, protoBare, 4, false, body)},
			{"bad-checksum decoy", buildIP4Ext(src, dst, protoBare, 64, true, body)},
		} {
			if tc.pkt == nil {
				t.Fatalf("%s: builder refused a normal payload", tc.name)
			}
			flags := binary.BigEndian.Uint16(tc.pkt[6:8])
			if flags&ipFlagDF == 0 {
				t.Fatalf("%s: DF is not set. Measured on the wire: the raw carrier's own data and an "+
					"ordinary Linux UDP socket both send DF=1, so a DF=0 packet is one bit that tells a "+
					"decoy apart from the flow it is imitating — and on flux and the spoof link it is "+
					"every packet of the tunnel", tc.name)
			}
			if frag := flags & 0x1fff; frag != 0 {
				t.Fatalf("%s: fragment offset is %d, want 0", tc.name, frag)
			}
			id := binary.BigEndian.Uint16(tc.pkt[4:6])
			if id == 0 {
				t.Fatalf("%s: Identification is 0. On an IP_HDRINCL socket the kernel would fill it in, "+
					"but the AF_PACKET paths (bad-checksum decoy, tcp-inject decoy, sni_mode=fake decoy) "+
					"bypass the kernel entirely and put this on the wire verbatim", tc.name)
			}
			seen[id] = true
		}
	}

	if len(seen) < 150 {
		t.Fatalf("192 packets produced only %d distinct Identification values — a near-constant ID is "+
			"the same tell as ID=0 wearing a different number", len(seen))
	}
}
