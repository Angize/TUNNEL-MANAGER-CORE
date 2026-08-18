package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	ephPubLen   = 32
	hsMACLen    = 16
	hsBodyLen   = ephPubLen + hsMACLen
	hsNonceLen  = 12
	hsPadLenLen = 1

	HandshakeCoreSize = hsNonceLen + hsPadLenLen + hsBodyLen

	hsTagInit = "core-hs-i"
	hsTagResp = "core-hs-r"
)

type Ephemeral struct {
	priv   [32]byte
	Pub    [32]byte
	nonce  [hsNonceLen]byte
	padLen byte
}

func GenerateEphemeral() (*Ephemeral, error) {
	e := &Ephemeral{}
	if _, err := io.ReadFull(rand.Reader, e.priv[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, e.nonce[:]); err != nil {
		return nil, err
	}
	var pb [1]byte
	if _, err := io.ReadFull(rand.Reader, pb[:]); err != nil {
		return nil, err
	}
	e.padLen = pb[0]
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.Pub[:], pub)
	return e, nil
}

func GenerateEphemeralNoPad() (*Ephemeral, error) {
	e, err := GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	e.padLen = 0
	return e, nil
}

func hsMACKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|hs-mac|" + psk))
	return k[:]
}

func hsMAC(psk, tag string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, hsMACKey(psk))
	m.Write([]byte(tag))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:hsMACLen]
}

func hsMaskKey(psk string) []byte {
	k := sha256.Sum256([]byte("tnl-core|v2|hs-mask|" + psk))
	return k[:]
}

func hsMask(psk string, nonce, buf []byte) {
	c, err := chacha20.NewUnauthenticatedCipher(hsMaskKey(psk), nonce)
	if err != nil {
		panic("crypto: handshake mask cipher: " + err.Error())
	}
	c.XORKeyStream(buf, buf)
}

func buildMsg(psk string, e *Ephemeral, mac []byte) []byte {
	out := make([]byte, HandshakeCoreSize+int(e.padLen))
	copy(out, e.nonce[:])
	m := out[hsNonceLen:]
	m[0] = e.padLen
	copy(m[hsPadLenLen:], e.Pub[:])
	copy(m[hsPadLenLen+ephPubLen:], mac)
	hsMask(psk, e.nonce[:], m)
	return out
}

func InitMsg(psk string, e *Ephemeral) []byte {
	return buildMsg(psk, e, hsMAC(psk, hsTagInit, e.Pub[:]))
}

func RespMsg(psk string, eInit [32]byte, e *Ephemeral) []byte {
	return buildMsg(psk, e, hsMAC(psk, hsTagResp, eInit[:], e.Pub[:]))
}

func parseBody(psk string, msg []byte) (pub [32]byte, mac []byte, err error) {
	if len(msg) < HandshakeCoreSize {
		return pub, nil, errors.New("handshake: short message")
	}
	body := make([]byte, hsPadLenLen+hsBodyLen)
	copy(body, msg[hsNonceLen:HandshakeCoreSize])
	hsMask(psk, msg[:hsNonceLen], body)
	copy(pub[:], body[hsPadLenLen:hsPadLenLen+ephPubLen])
	return pub, body[hsPadLenLen+ephPubLen : hsPadLenLen+hsBodyLen], nil
}

func ParseInit(psk string, msg []byte) (eInit [32]byte, err error) {
	pub, mac, err := parseBody(psk, msg)
	if err != nil {
		return eInit, err
	}
	if !hmac.Equal(mac, hsMAC(psk, hsTagInit, pub[:])) {
		return eInit, errors.New("handshake: init MAC mismatch")
	}
	return pub, nil
}

func ParseResp(psk string, eInit [32]byte, msg []byte) (eResp [32]byte, err error) {
	pub, mac, err := parseBody(psk, msg)
	if err != nil {
		return eResp, err
	}
	if !hmac.Equal(mac, hsMAC(psk, hsTagResp, eInit[:], pub[:])) {
		return eResp, errors.New("handshake: resp MAC mismatch")
	}
	return pub, nil
}

func ReadHandshake(r io.Reader, psk string) ([]byte, error) {
	core := make([]byte, HandshakeCoreSize)
	if _, err := io.ReadFull(r, core); err != nil {
		return nil, err
	}

	lead := []byte{core[hsNonceLen]}
	hsMask(psk, core[:hsNonceLen], lead)
	if pad := int(lead[0]); pad > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(pad)); err != nil {
			return nil, err
		}
	}
	return core, nil
}

func SessionSealer(cipherName, psk string, own *Ephemeral, peerPub, eInit, eResp [32]byte, isClient bool) (*Sealer, error) {
	name := ResolveCipher(cipherName)
	_, keyLen, err := aeadFactory(name)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(own.priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}

	ikm := append(append([]byte{}, shared...), []byte(psk)...)
	salt := append(append([]byte{}, eInit[:]...), eResp[:]...)
	kdf := hkdf.New(sha256.New, ikm, salt, []byte("tnl-core|v2|session|"+name))

	c2sKey := make([]byte, keyLen)
	s2cKey := make([]byte, keyLen)
	c2sMask := make([]byte, maskKeyLen)
	s2cMask := make([]byte, maskKeyLen)
	for _, b := range [][]byte{c2sKey, s2cKey, c2sMask, s2cMask} {
		if _, err := io.ReadFull(kdf, b); err != nil {
			return nil, err
		}
	}
	return sealerFromKeys(name, c2sKey, s2cKey, c2sMask, s2cMask, isClient)
}
