package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The frame is salt || mask(nonce) || ciphertext || tag, and the nonce is the only part with structure:
// a per-session constant prefix followed by a counter that steps by exactly one. Everything after it is
// AEAD output, indistinguishable from random without the key.
//
// The failure this file exists for is the one that leaves a WORKING tunnel: drop the mask and every
// frame still seals, opens and carries traffic, while the wire grows a constant field and a counter a
// watcher can lock onto. Nothing errors, nothing logs, throughput is unchanged. So the tests do not ask
// whether it works -- they look at the bytes that go out.

// wireNonce is the nonce field as it appears on the wire.
func wireNonce(t *testing.T, s *Sealer, frame []byte) []byte {
	t.Helper()
	return frame[maskSaltLen : maskSaltLen+s.sendAEAD.NonceSize()]
}

func TestTheNonceNeverGoesOutInTheClear(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, _ := ends(t, name)
			ns := cli.sendAEAD.NonceSize()
			for i := 1; i <= 50; i++ {
				frame, err := cli.Seal([]byte("payload"), nil)
				if err != nil {
					t.Fatal(err)
				}
				// what the nonce WOULD look like unmasked, rebuilt from the sealer's own state
				plain := make([]byte, ns)
				copy(plain, cli.prefix)
				binary.BigEndian.PutUint64(plain[ns-8:], uint64(i))
				if bytes.Equal(wireNonce(t, cli, frame), plain) {
					t.Fatalf("frame %d put its nonce on the wire unmasked: the session prefix is a "+
						"constant field and the counter steps by one, both visible to anyone watching", i)
				}
			}
		})
	}
}

// The prefix half of the nonce is CONSTANT for the life of a session. Unmasked, every frame of a
// session would carry the same bytes at the same offset -- the single easiest thing for a filter to
// key on. Masked with a fresh salt each frame, they must all differ.
func TestTheSessionPrefixIsNotAConstantFieldOnTheWire(t *testing.T) {
	cli, _ := ends(t, CipherAES256)
	ns := cli.sendAEAD.NonceSize()
	seen := map[string]int{}
	const frames = 200
	for i := 0; i < frames; i++ {
		frame, err := cli.Seal([]byte("payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(wireNonce(t, cli, frame)[:ns-8])]++
	}
	if len(seen) != frames {
		t.Fatalf("%d distinct prefixes across %d frames: the constant part is showing through",
			len(seen), frames)
	}
}

// And the counter half must not step by one on the wire. A masked counter walks at random; an unmasked
// one differs from its predecessor by exactly 1 every single time, which is a stronger signature than
// the constant prefix because it survives any per-frame randomisation of the rest.
func TestTheCounterDoesNotStepByOneOnTheWire(t *testing.T) {
	cli, _ := ends(t, CipherAES256)
	ns := cli.sendAEAD.NonceSize()
	var prev uint64
	steps := 0
	const frames = 200
	for i := 0; i < frames; i++ {
		frame, err := cli.Seal([]byte("payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		cur := binary.BigEndian.Uint64(wireNonce(t, cli, frame)[ns-8:])
		if i > 0 && cur == prev+1 {
			steps++
		}
		prev = cur
	}
	// a masked counter lands on prev+1 by chance with probability 2^-64 per frame
	if steps > 0 {
		t.Fatalf("the wire counter stepped by exactly one %d times in %d frames: it is not masked",
			steps, frames)
	}
}

// The bytes AFTER the nonce are the AEAD's own output and must be passed through untouched. Masking
// them as well is the cost this change removes; masking them by accident on ONE side only would break
// every frame, which the round trip catches -- but masking them on BOTH sides would work and simply
// burn the cpu again, so check the actual bytes.
func TestTheCiphertextIsNotMasked(t *testing.T) {
	cli, srv := ends(t, CipherAES256)
	ns := cli.sendAEAD.NonceSize()
	pt := bytes.Repeat([]byte{0x42}, 512)
	frame, err := cli.Seal(pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Recover the nonce the way the receiver does, then re-seal the same plaintext under it: the
	// ciphertext must come out byte-identical to what is on the wire, which is only true if the wire
	// copy was never masked.
	body := make([]byte, len(frame)-maskSaltLen)
	copy(body, frame[maskSaltLen:])
	if err := mask(srv.recvMask, frame[:maskSaltLen], body[:ns]); err != nil {
		t.Fatal(err)
	}
	want := srv.recvAEAD.Seal(nil, body[:ns], pt, nil)
	if !bytes.Equal(frame[maskSaltLen+ns:], want) {
		t.Fatal("the ciphertext on the wire is not the AEAD's raw output: something is still masking it")
	}
}

// Both ends must cover the same region. If they ever disagree the frame simply fails to authenticate,
// which is loud -- but this pins the pair so a change to one side cannot be made alone.
func TestBothEndsCoverTheSameBytes(t *testing.T) {
	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			cli, srv := ends(t, name)
			frame, err := cli.Seal([]byte("round trip"), []byte{7})
			if err != nil {
				t.Fatal(err)
			}
			_, seq, pt, err := srv.Open(frame, []byte{7})
			if err != nil {
				t.Fatalf("the two ends disagree about what is masked: %v", err)
			}
			if string(pt) != "round trip" || seq != 1 {
				t.Fatalf("opened to %q seq %d", pt, seq)
			}
		})
	}
}
