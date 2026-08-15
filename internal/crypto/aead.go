// Package crypto provides the AEAD sealing used by the core carrier: AES-256/128-GCM and
// ChaCha20/XChaCha20-Poly1305, selected by name, with both ends of a tunnel on the same cipher and PSK.
// Keys are derived PER DIRECTION, so each sealing key belongs to exactly one sealer and a frame captured
// one way is not valid the other. Every frame is XOR-masked (see Sealer) so no fixed bytes ride the wire.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	CipherAES256  = "aes-256-gcm"
	CipherAES128  = "aes-128-gcm"
	CipherChaCha  = "chacha20-poly1305"
	CipherXChaCha = "xchacha20-poly1305"
	CipherDefault = CipherAES256

	maskSaltLen = 12 // random per-frame salt seeding the wire mask (ChaCha20 nonce)
	maskKeyLen  = 32 // ChaCha20 key length for the wire mask
)

// Supported is the ordered list of concrete cipher names the core accepts.
var Supported = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

// Sealer seals and opens packet payloads with the configured AEAD, using direction-separated keys and a
// wire mask. Nonces are NOT random per message — a random nonce would collide after ~2^32 messages by
// the birthday bound, catastrophic for GCM. Each Sealer picks a random per-process prefix once and
// appends a strictly-increasing 64-bit counter, which doubles as the anti-replay sequence number.
type Sealer struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendMask []byte // ChaCha20 key masking our outbound frames
	recvMask []byte // ChaCha20 key unmasking the peer's inbound frames
	Name     string // resolved cipher name (never "auto")
	prefix   []byte // random per-process nonce prefix (NonceSize-8 bytes)
	ctr      atomic.Uint64
}

// ResolveCipher maps a requested name (or "auto") to a concrete cipher. Unknown names are returned
// unchanged so NewSealer can reject them. The short-form aliases (aes/chacha/xchacha/...) are gone:
// the panel and the node both whitelist the canonical names, so nothing in the fleet can emit one,
// and the shipped examples use the canonical spelling.
func ResolveCipher(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto":
		return CipherDefault // deterministic so both ends match regardless of CPU
	case CipherAES256:
		return CipherAES256
	case CipherAES128:
		return CipherAES128
	case CipherChaCha:
		return CipherChaCha
	case CipherXChaCha:
		return CipherXChaCha
	default:
		return name
	}
}

// deriveKey derives an n-byte key bound to a label (which encodes the purpose and
// direction) and the PSK. v2 domain: keys are NOT compatible with the old
// single-key scheme, which is intentional — both ends upgrade together.
func deriveKey(psk, label string, n int) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|" + label + "|" + psk))
	return k[:n] // n bytes (16 for AES-128, 32 for the rest)
}

// aeadFactory returns a constructor + key length for the named cipher.
func aeadFactory(name string) (mk func(key []byte) (cipher.AEAD, error), keyLen int, err error) {
	switch name {
	case CipherAES256:
		return func(k []byte) (cipher.AEAD, error) {
			b, e := aes.NewCipher(k)
			if e != nil {
				return nil, e
			}
			return cipher.NewGCM(b)
		}, 32, nil
	case CipherAES128:
		return func(k []byte) (cipher.AEAD, error) {
			b, e := aes.NewCipher(k)
			if e != nil {
				return nil, e
			}
			return cipher.NewGCM(b)
		}, 16, nil
	case CipherChaCha:
		return func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.New(k) }, 32, nil
	case CipherXChaCha:
		return func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(k) }, 32, nil
	default:
		return nil, 0, fmt.Errorf("unknown cipher %q (want one of aes-256-gcm, aes-128-gcm, chacha20-poly1305, xchacha20-poly1305)", name)
	}
}

// NewSealer builds a Sealer for the named cipher keyed statically from psk; isClient selects which
// direction key it seals with. VALIDATION/BOOTSTRAP ONLY — do NOT seal live traffic with it: the keys
// are a pure function of the PSK, so the send counter restarts from 0 every run and two processes would
// reuse (key, nonce) pairs. Real frames go through SessionSealer, salted by a fresh per-session ephemeral.
func NewSealer(cipherName, psk string, isClient bool) (*Sealer, error) {
	name := ResolveCipher(cipherName)
	_, keyLen, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	return sealerFromKeys(name,
		deriveKey(psk, "aead|c2s|"+name, keyLen),
		deriveKey(psk, "aead|s2c|"+name, keyLen),
		deriveKey(psk, "mask|c2s", maskKeyLen),
		deriveKey(psk, "mask|s2c", maskKeyLen),
		isClient)
}

// sealerFromKeys assembles a Sealer from already-derived per-direction key
// material (AEAD keys + wire-mask keys). The caller supplies the c→s and s→c
// keys; isClient wires send/recv to the right one. Used by both the static PSK
// path (NewSealer) and the ephemeral handshake path.
func sealerFromKeys(name string, c2sKey, s2cKey, c2sMask, s2cMask []byte, isClient bool) (*Sealer, error) {
	mk, _, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	s := &Sealer{Name: name}
	var sendKey, recvKey []byte
	if isClient {
		sendKey, recvKey = c2sKey, s2cKey
		s.sendMask, s.recvMask = c2sMask, s2cMask
	} else {
		sendKey, recvKey = s2cKey, c2sKey
		s.sendMask, s.recvMask = s2cMask, c2sMask
	}
	if s.sendAEAD, err = mk(sendKey); err != nil {
		return nil, err
	}
	if s.recvAEAD, err = mk(recvKey); err != nil {
		return nil, err
	}
	s.prefix = make([]byte, s.sendAEAD.NonceSize()-8) // 8 bytes reserved for the counter
	if _, err := io.ReadFull(rand.Reader, s.prefix); err != nil {
		return nil, err
	}
	return s, nil
}

// sessionID compresses a nonce prefix into a 64-bit id used only to key the
// receiver's anti-replay window. A collision merely resets a window early, which
// is safe, so a right-aligned truncation to 8 bytes is enough.
func sessionID(prefix []byte) uint64 {
	var b [8]byte
	n := len(prefix)
	if n > 8 {
		n = 8
	}
	copy(b[8-n:], prefix[:n])
	return binary.BigEndian.Uint64(b[:])
}

// mask XORs buf in place with the ChaCha20 keystream keyed by (key, salt).
func mask(key, salt, buf []byte) error {
	c, err := chacha20.NewUnauthenticatedCipher(key, salt)
	if err != nil {
		return err
	}
	c.XORKeyStream(buf, buf)
	return nil
}

// Seal returns salt || mask(nonce||ciphertext||tag). aad is authenticated but not
// transmitted (callers pass the cleartext frame header so it cannot be flipped).
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	// ONE buffer, sized for the whole frame, built in place. The obvious spelling -- allocate a nonce,
	// let Seal append to it, then allocate the output and copy -- is three allocations and a full-frame
	// copy on a path that runs per packet.
	ns := s.sendAEAD.NonceSize()
	out := make([]byte, maskSaltLen+ns, maskSaltLen+ns+len(plaintext)+s.sendAEAD.Overhead())
	// Buffered, not weakened: RandRead hands out crypto/rand's own bytes a block at a time, because
	// reading them one salt at a time is a syscall per packet. See randpool.go.
	if err := RandRead(out[:maskSaltLen]); err != nil {
		return nil, err
	}
	nonce := out[maskSaltLen:]
	copy(nonce, s.prefix)
	binary.BigEndian.PutUint64(nonce[ns-8:], s.ctr.Add(1))
	// The nonce lives INSIDE out, and Seal appends past out's length -- so it writes only after the
	// nonce it is reading. The round-trip tests cover every cipher precisely because that is an
	// assumption about the AEAD implementations rather than something the signature promises.
	out = s.sendAEAD.Seal(out, nonce, plaintext, aad) // salt||nonce||ct||tag
	if err := mask(s.sendMask, out[:maskSaltLen], out[maskSaltLen:]); err != nil {
		return nil, err
	}
	return out, nil
}

// Open reverses Seal, returning the sender's session id and per-message sequence
// number (both from the authenticated nonce) alongside the plaintext. aad must
// match the value passed to Seal. Any authentication failure returns an error.
func (s *Sealer) Open(wire, aad []byte) (session uint64, seq uint64, pt []byte, err error) {
	ns := s.recvAEAD.NonceSize()
	if len(wire) < maskSaltLen+ns {
		return 0, 0, nil, errors.New("sealed payload too short")
	}
	body := make([]byte, len(wire)-maskSaltLen)
	copy(body, wire[maskSaltLen:])
	if err := mask(s.recvMask, wire[:maskSaltLen], body); err != nil {
		return 0, 0, nil, err
	}
	nonce := body[:ns]
	// Decrypt into the ciphertext's own storage. Passing nil makes the AEAD allocate a second buffer
	// the size of the packet, every packet; ciphertext[:0] as dst is the documented way to avoid it.
	pt, err = s.recvAEAD.Open(body[ns:][:0], nonce, body[ns:], aad)
	if err != nil {
		return 0, 0, nil, err
	}
	return sessionID(nonce[:ns-8]), binary.BigEndian.Uint64(nonce[ns-8:]), pt, nil
}
