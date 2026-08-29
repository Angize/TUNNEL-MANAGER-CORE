package packet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

const (
	obfsSaltLen = 24

	obfsDataPadMax = 64
	obfsCtrlPadMax = 256

	obfsInnerHdr = 3
)

func deriveObfsKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core-obfs|v1|len|" + psk))
	return k[:32]
}

func newObfsStream(psk string, salt []byte) (*chacha20.Cipher, error) {
	return chacha20.NewUnauthenticatedCipher(deriveObfsKey(psk), salt)
}

func randUint(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	n := uint32(max) + 1
	limit := (0xFFFFFFFF/n)*n - 1
	var b [4]byte
	for {
		if err := crypto.RandRead(b[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint32(b[:])
		if v <= limit {
			return int(v % n), nil
		}
	}
}

func obfsSeal(s Sealer, typ byte, payload []byte, padMax int) ([]byte, error) {
	n, err := randUint(padMax)
	if err != nil {
		return nil, err
	}
	inner := make([]byte, obfsInnerHdr+len(payload)+n)
	inner[0] = typ
	binary.BigEndian.PutUint16(inner[1:3], uint16(len(payload)))
	copy(inner[obfsInnerHdr:], payload)
	return s.Seal(inner, nil)
}

func obfsOpen(s Sealer, sealed []byte) (typ byte, session uint64, seq uint64, payload []byte, err error) {
	session, seq, inner, err := s.Open(sealed, nil)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if len(inner) < obfsInnerHdr {
		return 0, 0, 0, nil, errors.New("obfs: short inner frame")
	}
	realLen := int(binary.BigEndian.Uint16(inner[1:3]))
	if obfsInnerHdr+realLen > len(inner) {
		return 0, 0, 0, nil, errors.New("obfs: inner length overflow")
	}
	return inner[0], session, seq, inner[obfsInnerHdr : obfsInnerHdr+realLen], nil
}

func padMaxFor(typ byte) int {
	if typ == typeData {
		return obfsDataPadMax
	}
	return obfsCtrlPadMax
}

func frac53(b []byte) float64 {
	return float64(binary.BigEndian.Uint64(b)>>11) / float64(uint64(1)<<53)
}

func keepaliveInterval(base time.Duration, psk string) time.Duration {
	if base <= 0 {
		return base
	}

	h := sha256.Sum256([]byte("tnl-core|ka-phase|" + psk))
	mean := float64(base) * (0.85 + 0.35*frac53(h[:8]))
	var rb [16]byte
	if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
		return time.Duration(mean)
	}

	spread := 1.0 + 0.68*((frac53(rb[0:8])+frac53(rb[8:16]))/2.0-0.5)
	d := mean * spread
	if lo := float64(base) * 0.6; d < lo {
		d = lo
	}
	if hi := float64(base) * 1.3; d > hi {
		d = hi
	}
	return time.Duration(d)
}

func jitterFrac(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	var rb [8]byte
	if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
		return d
	}
	return time.Duration(float64(d) * (0.7 + 0.6*frac53(rb[:])))
}
