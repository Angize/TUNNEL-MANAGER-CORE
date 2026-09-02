package packet

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestHandshakeRetransmitIsJittered(t *testing.T) {
	const draws = 500
	lo, hi := time.Duration(float64(handshakeRetransmit)*0.7), time.Duration(float64(handshakeRetransmit)*1.3)
	seen := map[time.Duration]struct{}{}
	for i := 0; i < draws; i++ {
		d := handshakeRetransmitWait()
		if d < lo || d > hi {
			t.Fatalf("retransmit wait %v is outside [%v,%v]: a wait that can collapse to zero spins the "+
				"loop, and one that can grow without bound stalls failover", d, lo, hi)
		}
		seen[d] = struct{}{}
	}
	if len(seen) < draws/2 {
		t.Fatalf("only %d distinct waits in %d draws — the handshake retransmit is effectively fixed, "+
			"which is the timing signature this exists to remove", len(seen), draws)
	}
}

func TestNoCarrierRetransmitsOnAFixedClock(t *testing.T) {
	for _, f := range []string{"udp.go", "raw_linux.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		s := string(src)
		if strings.Contains(s, "wait = time.Second") {
			t.Errorf("%s still sets the handshake retransmit to a bare time.Second; "+
				"use handshakeRetransmitWait()", f)
		}
		if !strings.Contains(s, "wait = handshakeRetransmitWait()") {
			t.Errorf("%s no longer takes its retransmit wait from handshakeRetransmitWait() — "+
				"either it was renamed (update this test) or the carrier went back to a fixed clock", f)
		}
	}
}
