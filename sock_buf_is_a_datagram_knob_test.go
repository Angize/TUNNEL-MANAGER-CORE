package main

import (
	"strings"
	"testing"
)

// sock_buf is defaulted for every transport and the panel writes it into every core link, but only
// udp and raw ever reach applyConnSockBuf. The obvious fix -- apply it to the stream carriers too --
// was MEASURED on the fleet link (IR02 -> DE02, 72ms RTT) before being written:
//
//	kernel autotuning   1123 Mbit/s
//	pinned to 4 MB       619 Mbit/s
//
// net.ipv4.tcp_rmem tops out at 16 MB on those hosts, so pinning a stream socket at the 4 MB default
// swaps a 16 MB autotuned ceiling for a fixed 4 MB one and turns tcp_moderate_rcvbuf off for that
// socket. It would also hand every one of the 128 pre-auth sockets a forced buffer. So the carriers
// that ignore the knob keep ignoring it, and the operator is told instead of left to wonder why the
// number changed nothing.
func TestSockBufSaysNothingToTheCarriersThatReadIt(t *testing.T) {
	for _, transport := range []string{"", "udp", "raw"} {
		if note := sockBufNote(transport, 4<<20); note != "" {
			t.Errorf("transport %q reads sock_buf and was warned anyway: %q", transport, note)
		}
	}
}

func TestSockBufWarnsTheCarriersThatIgnoreIt(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "dns"} {
		note := sockBufNote(transport, 4<<20)
		if note == "" {
			t.Errorf("transport %q ignores sock_buf silently; the operator raises the number, sees no "+
				"change, and has nothing to read", transport)
			continue
		}
		if !strings.Contains(note, transport) {
			t.Errorf("the warning for %q does not name the carrier: %q", transport, note)
		}
		if !strings.Contains(note, "619 Mbit") || !strings.Contains(note, "1123") {
			t.Errorf("the warning for %q carries no measurement: %q. An operator told only that a knob "+
				"is ignored will reasonably ask for it to be honoured -- the number is why it is not",
				transport, note)
		}
	}
}

// Zero means unset, and an unset knob is not worth a line on any carrier.
func TestAnUnsetSockBufWarnsNobody(t *testing.T) {
	for _, transport := range []string{"", "udp", "raw", "tcp", "ws", "dns"} {
		if note := sockBufNote(transport, 0); note != "" {
			t.Errorf("transport %q was warned about a knob that is not set: %q", transport, note)
		}
	}
}
