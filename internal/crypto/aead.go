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

	maskSaltLen = 12
	maskKeyLen  = 32
)

var Supported = []string{CipherAES256, CipherAES128, CipherChaCha, CipherXChaCha}

type Sealer struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendMask []byte
	recvMask []byte
	Name     string
	prefix   []byte
	ctr      atomic.Uint64
}

func ResolveCipher(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto":
		return CipherDefault
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

func deriveKey(psk, label string, n int) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|" + label + "|" + psk))
	return k[:n]
}

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
	s.prefix = make([]byte, s.sendAEAD.NonceSize()-8)
	if _, err := io.ReadFull(rand.Reader, s.prefix); err != nil {
		return nil, err
	}
	return s, nil
}

func sessionID(prefix []byte) uint64 {
	var b [8]byte
	n := len(prefix)
	if n > 8 {
		n = 8
	}
	copy(b[8-n:], prefix[:n])
	return binary.BigEndian.Uint64(b[:])
}

func mask(key, salt, buf []byte) error {
	c, err := chacha20.NewUnauthenticatedCipher(key, salt)
	if err != nil {
		return err
	}
	c.XORKeyStream(buf, buf)
	return nil
}

func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	ns := s.sendAEAD.NonceSize()
	out := make([]byte, maskSaltLen+ns, maskSaltLen+ns+len(plaintext)+s.sendAEAD.Overhead())

	if err := RandRead(out[:maskSaltLen]); err != nil {
		return nil, err
	}
	nonce := out[maskSaltLen:]
	copy(nonce, s.prefix)
	binary.BigEndian.PutUint64(nonce[ns-8:], s.ctr.Add(1))

	out = s.sendAEAD.Seal(out, nonce, plaintext, aad)

	if err := mask(s.sendMask, out[:maskSaltLen], out[maskSaltLen:maskSaltLen+ns]); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Sealer) Frame(lead, innerLen int) (buf, head, inner []byte) {
	off := lead + maskSaltLen + s.sendAEAD.NonceSize()
	buf = make([]byte, off+innerLen, off+innerLen+s.sendAEAD.Overhead())
	return buf, buf[:lead], buf[off:]
}

func (s *Sealer) SealInPlace(buf, inner, aad []byte) ([]byte, error) {
	ns := s.sendAEAD.NonceSize()
	off := len(buf) - len(inner)
	if off < maskSaltLen+ns || cap(buf) < len(buf)+s.sendAEAD.Overhead() {
		return nil, errors.New("seal: frame buffer was not built by Frame")
	}
	salt, nonce := buf[off-maskSaltLen-ns:off-ns], buf[off-ns:off]
	if err := RandRead(salt); err != nil {
		return nil, err
	}
	copy(nonce, s.prefix)
	binary.BigEndian.PutUint64(nonce[ns-8:], s.ctr.Add(1))

	out := s.sendAEAD.Seal(inner[:0], nonce, inner, aad)

	if err := mask(s.sendMask, salt, nonce); err != nil {
		return nil, err
	}
	return buf[:off+len(out)], nil
}

func (s *Sealer) Open(wire, aad []byte) (session uint64, seq uint64, pt []byte, err error) {
	ns := s.recvAEAD.NonceSize()
	if len(wire) < maskSaltLen+ns {
		return 0, 0, nil, errors.New("sealed payload too short")
	}
	body := make([]byte, len(wire)-maskSaltLen)
	copy(body, wire[maskSaltLen:])

	if err := mask(s.recvMask, wire[:maskSaltLen], body[:ns]); err != nil {
		return 0, 0, nil, err
	}
	nonce := body[:ns]

	pt, err = s.recvAEAD.Open(body[ns:][:0], nonce, body[ns:], aad)
	if err != nil {
		return 0, 0, nil, err
	}
	return sessionID(nonce[:ns-8]), binary.BigEndian.Uint64(nonce[ns-8:]), pt, nil
}
