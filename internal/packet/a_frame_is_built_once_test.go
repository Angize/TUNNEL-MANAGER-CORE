package packet

import (
	"bytes"
	"testing"
)

// obfsSeal used to build every frame twice. It allocated an inner buffer, copied the whole payload
// into it, and handed that to Seal, which allocated a second buffer and encrypted across. Two
// allocations and two 1.4 KB copies for a job that needs one of each, on every packet -- about 126
// MB/s of pure allocation churn at 90k packets per second.
//
// Measured on DE02 before the change, sealing a 1400-byte packet:
//
//	plain framing        1231 ns/op
//	obfs, no padding     1390 ns/op   +12.9%
//	obfs, 0..64 padding  1571 ns/op   +27.6%
//	randUint alone       33.6 ns/op   -- so the random draw was never the cost
//
// The frame is now one buffer laid out as [maskSalt][nonce][typ][len][payload][pad] with room for the
// tag, and the AEAD encrypts the inner region in place.
func TestAnObfsFrameIsBuiltInOneBuffer(t *testing.T) {
	cli, srv := mustPair(t, "one-buffer-psk-0123456789abcdef")
	payload := bytes.Repeat([]byte{0xC7}, 1400)

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsSeal(cli, typeData, payload, obfsDataPadMax); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 1 {
		t.Errorf("obfsSeal allocates %.0f times per frame, want 1", allocs)
	}

	for _, pad := range []int{0, 1, obfsDataPadMax, obfsCtrlPadMax} {
		for _, n := range []int{0, 1, 1400} {
			p := bytes.Repeat([]byte{0x5A}, n)
			wire, err := obfsSeal(cli, typePing, p, pad)
			if err != nil {
				t.Fatalf("pad %d len %d: %v", pad, n, err)
			}
			typ, _, _, got, err := obfsOpen(srv, wire)
			if err != nil {
				t.Fatalf("pad %d len %d did not open: %v", pad, n, err)
			}
			if typ != typePing {
				t.Fatalf("pad %d len %d: type came back %d", pad, n, typ)
			}
			if !bytes.Equal(got, p) {
				t.Fatalf("pad %d len %d round-tripped to %d bytes", pad, n, len(got))
			}
		}
	}
}

// The padding still varies the length, which is the half of obfs that a byte-level fix cannot buy.
func TestObfsStillVariesTheLength(t *testing.T) {
	cli, _ := mustPair(t, "one-buffer-psk-0123456789abcdef")
	payload := bytes.Repeat([]byte{0x11}, 200)
	seen := map[int]bool{}
	for i := 0; i < 400; i++ {
		wire, err := obfsSeal(cli, typeData, payload, obfsDataPadMax)
		if err != nil {
			t.Fatal(err)
		}
		seen[len(wire)] = true
	}
	if len(seen) < 32 {
		t.Errorf("400 frames of one payload produced only %d distinct wire lengths", len(seen))
	}
}
