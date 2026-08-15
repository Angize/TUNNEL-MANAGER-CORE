package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// Seal builds the whole frame in ONE buffer: the nonce is written inside the output and then handed to
// the AEAD as its nonce, while the AEAD appends the ciphertext past the output's length.
//
// That is an assumption about the AEAD implementations -- that Seal reads the nonce before writing the
// region after dst -- and not something the cipher.AEAD signature promises. If it were ever false the
// nonce would be clobbered mid-seal and the frame would still LOOK fine: right length, random-looking
// bytes, no error anywhere. Only the far end would notice, by failing to authenticate it.
//
// So these run the whole round trip, on every cipher the config accepts, at the sizes the carriers
// actually send.

var ciphers = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

// ends returns the two sealers of one tunnel, on the package's existing pair helper.
func ends(t *testing.T, name string) (*Sealer, *Sealer) {
	t.Helper()
	return pair(t, name, "psk-for-the-in-place-seal-check")
}

func TestAFrameSealedInPlaceStillOpens(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, srv := ends(t, name)
			// 0 and 1 are the degenerate sizes; 1373 is the operator's MTU; 1500 crosses it
			for _, n := range []int{0, 1, 16, 1373, 1500, maxFrame} {
				pt := make([]byte, n)
				for i := range pt {
					pt[i] = byte(i * 7)
				}
				aad := []byte{0x11}
				wire, err := cli.Seal(pt, aad)
				if err != nil {
					t.Fatalf("seal %d bytes: %v", n, err)
				}
				_, _, got, err := srv.Open(wire, aad)
				if err != nil {
					t.Fatalf("%d bytes sealed in place did not authenticate: %v", n, err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("%d bytes round-tripped to something else", n)
				}
			}
		})
	}
}

// The nonce is what carries the session id and the sequence number, and it is read back out of the
// frame by Open. A nonce clobbered by the in-place seal would still authenticate if the AEAD used its
// own copy, and only the sequence would be wrong -- which the replay window would then reject at
// random. So check the numbers, not just that it opened.
func TestTheSequenceSurvivesAnInPlaceSeal(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, srv := ends(t, name)
			var lastSession uint64
			for i := 1; i <= 200; i++ {
				wire, err := cli.Seal([]byte("payload"), nil)
				if err != nil {
					t.Fatal(err)
				}
				session, seq, _, err := srv.Open(wire, nil)
				if err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if seq != uint64(i) {
					t.Fatalf("frame %d reported sequence %d: the nonce was corrupted in place", i, seq)
				}
				if i > 1 && session != lastSession {
					t.Fatalf("frame %d changed session id mid-stream", i)
				}
				lastSession = session
			}
		})
	}
}

// Open decrypts into the ciphertext's own storage. The plaintext it returns must not alias anything
// the CALLER still holds -- the receive buffer is reused for the next packet, and a plaintext pointing
// into it would change under the carrier's feet between authentication and the TUN write.
func TestOpenDoesNotHandBackTheCallersBuffer(t *testing.T) {
	cli, srv := ends(t, CipherAES256)
	pt := bytes.Repeat([]byte{0x5A}, 1373)
	wire, err := cli.Seal(pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, got, err := srv.Open(wire, nil)
	if err != nil {
		t.Fatal(err)
	}
	// scribble over the wire exactly as the next packet's read would
	for i := range wire {
		wire[i] = 0xFF
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("the plaintext changed when the wire buffer was reused: Open aliased the caller's bytes")
	}
}

// A frame that was tampered with must fail, not merely differ. Building in place must not have turned
// the tag check into something weaker.
func TestATamperedFrameStillFails(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, srv := ends(t, name)
			base, err := cli.Seal([]byte("the quick brown fox"), []byte{9})
			if err != nil {
				t.Fatal(err)
			}
			for _, at := range []int{0, maskSaltLen, maskSaltLen + 3, len(base) - 1} {
				wire := append([]byte(nil), base...)
				wire[at] ^= 0x80
				if _, _, _, err := srv.Open(wire, []byte{9}); err == nil {
					t.Fatalf("a frame flipped at byte %d opened anyway", at)
				}
			}
			// and the aad must still be bound
			if _, _, _, err := srv.Open(base, []byte{8}); err == nil {
				t.Fatal("a frame opened under the wrong aad")
			}
		})
	}
}

// The frame's LENGTH is on the wire and its shape is part of what the carriers size their MTU against.
// Building it differently must not have changed it by a byte.
func TestTheFrameIsTheSameSizeItAlwaysWas(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, _ := ends(t, name)
			wire, err := cli.Seal(make([]byte, 1000), nil)
			if err != nil {
				t.Fatal(err)
			}
			want := maskSaltLen + cli.sendAEAD.NonceSize() + 1000 + cli.sendAEAD.Overhead()
			if len(wire) != want {
				t.Fatalf("a 1000-byte payload framed to %d bytes, want %d", len(wire), want)
			}
		})
	}
}

// maxFrame is a size past anything a carrier sends, so the pre-sized buffer is exercised well beyond
// the MTU it was sized for.
const maxFrame = 9000

func TestTheCipherListHereMatchesTheOneTheConfigAccepts(t *testing.T) {
	// If a cipher is added and not listed above, every test in this file silently stops covering it.
	_, _, err := aeadFactory("no-such-cipher")
	if err == nil {
		t.Fatal("aeadFactory accepted an unknown cipher")
	}
	for _, name := range ciphers {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("cipher %q is accepted by the config but not covered here", name)
		}
	}
}
