//go:build linux

package packet

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestDegradedSendDropsOnlyTheSourceBoundProfiles(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	unbindable := net.IPv4(203, 0, 113, 9)
	for _, tc := range []struct {
		profile   string
		proto     int
		delivered bool
	}{
		{"bare", protoBare, true},
		{"icmp", protoICMP, true},
		{"udp", protoUDP, false},
		{"tcp", protoTCP, false},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			rx, err := net.ListenIP("ip4:"+strconv.Itoa(tc.proto), &net.IPAddr{IP: lo})
			if err != nil {
				t.Skipf("raw sockets are not permitted here (%v) — this test needs CAP_NET_RAW", err)
			}
			defer rx.Close()
			tx, err := net.ListenIP("ip4:"+strconv.Itoa(tc.proto), &net.IPAddr{IP: net.IPv4zero})
			if err != nil {
				t.Skipf("raw sockets are not permitted here (%v)", err)
			}
			defer tx.Close()

			r := &Raw{conn: tx, profile: tc.profile, proto: tc.proto, isClient: false, fakeFd: -1}
			src := unbindable
			r.replySrc.Store(&src)

			marker := bytes.Repeat([]byte{0xC8}, 40)
			pkt := rawEncap(tc.profile, marker, unbindable, lo, false, 0xBEEF, 0, 0, 7, 9, 0x11223344, 0, 0, tcpPshAck)
			sendViaConn(r, pkt, &net.IPAddr{IP: lo})

			buf := make([]byte, 2048)
			got := false
			deadline := time.Now().Add(700 * time.Millisecond)
			for time.Now().Before(deadline) {
				rx.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				n, _, err := rx.ReadFromIP(buf)
				if err != nil {
					continue
				}
				if bytes.Contains(buf[:n], marker) {
					got = true
					break
				}
			}
			if got != tc.delivered {
				if tc.delivered {
					t.Fatalf("raw/%s: the degraded send was dropped, losing a packet whose bytes were perfectly valid from any source", tc.profile)
				}
				t.Fatalf("raw/%s: the packet went out from a source it was NOT checksummed for — every one of these carries a wrong L4 checksum, which a stateful middlebox drops and a DPI reads as a forged flow", tc.profile)
			}
		})
	}
}
