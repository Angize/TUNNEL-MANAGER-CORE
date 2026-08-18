package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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

	if steps > 0 {
		t.Fatalf("the wire counter stepped by exactly one %d times in %d frames: it is not masked",
			steps, frames)
	}
}

func TestTheCiphertextIsNotMasked(t *testing.T) {
	cli, srv := ends(t, CipherAES256)
	ns := cli.sendAEAD.NonceSize()
	pt := bytes.Repeat([]byte{0x42}, 512)
	frame, err := cli.Seal(pt, nil)
	if err != nil {
		t.Fatal(err)
	}

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
