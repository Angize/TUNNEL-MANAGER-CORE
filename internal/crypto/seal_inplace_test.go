package crypto

import (
	"bytes"
	"strings"
	"testing"
)

var ciphers = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

func ends(t *testing.T, name string) (*Sealer, *Sealer) {
	t.Helper()
	return pair(t, name, "psk-for-the-in-place-seal-check")
}

func TestAFrameSealedInPlaceStillOpens(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, srv := ends(t, name)

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

	for i := range wire {
		wire[i] = 0xFF
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("the plaintext changed when the wire buffer was reused: Open aliased the caller's bytes")
	}
}

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

			if _, _, _, err := srv.Open(base, []byte{8}); err == nil {
				t.Fatal("a frame opened under the wrong aad")
			}
		})
	}
}

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

const maxFrame = 9000

func TestTheCipherListHereMatchesTheOneTheConfigAccepts(t *testing.T) {

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
