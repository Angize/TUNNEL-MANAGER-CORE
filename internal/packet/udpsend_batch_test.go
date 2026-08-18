package packet

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func TestAFramedPacketDoesNotAliasTheReadBuffer(t *testing.T) {
	sealer, err := crypto.NewSealer("aes-256-gcm", "batch-test-psk-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		s    Sealer
		obfs bool
	}{
		{"clear", nil, false},
		{"crypto", sealer, false},
		{"crypto+obfs", sealer, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, maxDatagram)
			first := bytes.Repeat([]byte{0xA1}, 200)
			copy(buf, first)
			frame, err := sealBody(tc.s, tc.obfs, typeData, buf[:len(first)], padMaxFor(typeData))
			if err != nil {
				t.Fatal(err)
			}
			held := append([]byte(nil), frame...)

			copy(buf, bytes.Repeat([]byte{0x5E}, 200))
			if !bytes.Equal(frame, held) {
				t.Fatal("the framed packet changed when the read buffer was refilled: it aliases the " +
					"buffer, so a batch would send the same bytes for every packet in the burst")
			}
		})
	}
}

func TestTheUDPBatchDrainNeverWaits(t *testing.T) {
	b, err := os.ReadFile("udp.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "for !tx.full() {")
	if i < 0 {
		t.Fatal("the drain loop is not the expected shape; check what bounds it now")
	}
	body := src[i:]
	if end := strings.Index(body, "\n\t\t\t}"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "TryRead") {
		t.Fatal("the drain does not use TryRead, so it can block waiting for a packet that never comes")
	}
}
