package crypto

import (
	"bytes"
	"testing"
)

func pair(t *testing.T, cipher, psk string) (client, server *Sealer) {
	t.Helper()
	c, err := NewSealer(cipher, psk, true)
	if err != nil {
		t.Fatalf("client NewSealer(%s): %v", cipher, err)
	}
	s, err := NewSealer(cipher, psk, false)
	if err != nil {
		t.Fatalf("server NewSealer(%s): %v", cipher, err)
	}
	return c, s
}

func TestSealOpenRoundTripAllCiphers(t *testing.T) {
	pt := []byte("the quick brown fox jumps over the lazy dog")
	for _, name := range Supported {
		c, s := pair(t, name, "correct horse battery staple")
		if c.Name != name {
			t.Fatalf("resolved name %q != %q", c.Name, name)
		}

		ct, err := c.Seal(pt, nil)
		if err != nil {
			t.Fatalf("%s: seal: %v", name, err)
		}
		if bytes.Contains(ct, pt) {
			t.Fatalf("%s: ciphertext leaks plaintext", name)
		}
		if _, _, got, err := s.Open(ct, nil); err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("%s: c->s round trip: err=%v", name, err)
		}

		ct2, _ := s.Seal(pt, nil)
		if _, _, got, err := c.Open(ct2, nil); err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("%s: s->c round trip: err=%v", name, err)
		}
	}
}

func TestResolveCipher(t *testing.T) {
	cases := map[string]string{
		"": CipherAES256, "auto": CipherAES256, "AES-256-GCM": CipherAES256,
		CipherAES128: CipherAES128, CipherChaCha: CipherChaCha, CipherXChaCha: CipherXChaCha,
	}

	if got := ResolveCipher("chacha"); got != "chacha" {
		t.Fatalf("removed alias %q should pass through unchanged, got %q", "chacha", got)
	}
	for in, want := range cases {
		if got := ResolveCipher(in); got != want {
			t.Fatalf("ResolveCipher(%q)=%q want %q", in, got, want)
		}
	}
	if _, err := NewSealer("blowfish", "k", true); err == nil {
		t.Fatal("unknown cipher should error")
	}
}

func TestNonceIsFresh(t *testing.T) {
	c, _ := pair(t, "chacha20-poly1305", "k")
	a, _ := c.Seal([]byte("x"), nil)
	b, _ := c.Seal([]byte("x"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of identical plaintext are identical (nonce/salt reuse?)")
	}
}

func TestPerDirectionKeys(t *testing.T) {
	c1, s := pair(t, "aes-256-gcm", "dir-psk")
	c2, _ := NewSealer("aes-256-gcm", "dir-psk", true)
	ct, _ := c1.Seal([]byte("secret"), nil)
	if _, _, _, err := c2.Open(ct, nil); err == nil {
		t.Fatal("a client opened another client's same-direction frame (keys not direction-separated)")
	}
	if _, _, _, err := s.Open(ct, nil); err != nil {
		t.Fatalf("server could not open the client's frame: %v", err)
	}
}

func TestNoZeroNonceSignature(t *testing.T) {
	c, _ := pair(t, "chacha20-poly1305", "mask-psk-000")
	const N = 512

	zeroRuns := 0
	saltsSeen := map[[maskSaltLen]byte]bool{}
	for i := 0; i < N; i++ {
		ct, _ := c.Seal([]byte("d"), nil)
		w := ct[maskSaltLen+4 : maskSaltLen+8]
		if w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 {
			zeroRuns++
		}
		var salt [maskSaltLen]byte
		copy(salt[:], ct[:maskSaltLen])
		saltsSeen[salt] = true
	}
	if zeroRuns > 4 {
		t.Fatalf("zero-nonce DPI signature still present in %d/%d frames", zeroRuns, N)
	}
	if len(saltsSeen) < N {
		t.Fatalf("per-frame salt not unique: %d distinct over %d frames", len(saltsSeen), N)
	}
}

func TestAADAuthenticated(t *testing.T) {
	c, s := pair(t, "chacha20-poly1305", "aad-psk")
	ct, _ := c.Seal([]byte("payload"), []byte{0x00})
	if _, _, _, err := s.Open(ct, []byte{0x01}); err == nil {
		t.Fatal("a flipped aad (type byte) opened without error")
	}
	if _, _, got, err := s.Open(ct, []byte{0x00}); err != nil || !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("matching aad failed to open: %v", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	c1, _ := pair(t, "aes-256-gcm", "key-one")
	_, s2 := pair(t, "aes-256-gcm", "key-two")
	ct, _ := c1.Seal([]byte("secret"), nil)
	if _, _, _, err := s2.Open(ct, nil); err == nil {
		t.Fatal("open with wrong psk should fail")
	}
}

func TestCipherMismatchFails(t *testing.T) {
	c, _ := pair(t, "aes-256-gcm", "same-psk")
	_, s := pair(t, "chacha20-poly1305", "same-psk")
	ct, _ := c.Seal([]byte("secret"), nil)
	if _, _, _, err := s.Open(ct, nil); err == nil {
		t.Fatal("aes ciphertext opened by chacha should fail")
	}
}

func TestTamperFails(t *testing.T) {
	c, s := pair(t, "xchacha20-poly1305", "k")
	ct, _ := c.Seal([]byte("secret"), nil)
	ct[len(ct)-1] ^= 0x01
	if _, _, _, err := s.Open(ct, nil); err == nil {
		t.Fatal("open of tampered ciphertext should fail")
	}
}

func TestShortInputFails(t *testing.T) {
	_, s := pair(t, "aes-256-gcm", "k")
	if _, _, _, err := s.Open([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("Open of a too-short frame should error, not panic")
	}
}

func TestSeqIncrementsMonotonically(t *testing.T) {
	for _, name := range Supported {
		c, s := pair(t, name, "seq-psk")
		var prev uint64
		seen := map[uint64]bool{}
		for i := 0; i < 1000; i++ {
			ct, _ := c.Seal([]byte("d"), nil)
			_, seq, _, err := s.Open(ct, nil)
			if err != nil {
				t.Fatalf("%s: open: %v", name, err)
			}
			if seen[seq] {
				t.Fatalf("%s: seq %d reused (nonce reuse!)", name, seq)
			}
			seen[seq] = true
			if i > 0 && seq != prev+1 {
				t.Fatalf("%s: seq jumped %d -> %d", name, prev, seq)
			}
			prev = seq
		}
	}
}

func TestSessionDiffersPerProcess(t *testing.T) {
	a, s := pair(t, "aes-256-gcm", "same-psk-both-ends")
	b, _ := NewSealer("aes-256-gcm", "same-psk-both-ends", true)
	ca, _ := a.Seal([]byte("x"), nil)
	cb, _ := b.Seal([]byte("x"), nil)
	sa, _, _, err := s.Open(ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	sb, _, _, err := s.Open(cb, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sa == sb {
		t.Fatal("two distinct sender sessions report the same session id")
	}
}
