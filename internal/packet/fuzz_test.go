package packet

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func FuzzGrpcUnhunk(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a})
	f.Add([]byte{0x0a, 0x05, 1, 2, 3, 4, 5})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = grpcUnhunk(data)
	})
}

func FuzzGrpcDeframe(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 3, 0x0a, 0x01, 0x41})
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &grpcDeframingReader{r: bytes.NewReader(data)}
		buf := make([]byte, 512)
		for i := 0; i < 10000; i++ {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	})
}

func FuzzReadWSFrame(f *testing.F) {
	f.Add([]byte{0x82, 0x03, 1, 2, 3})
	f.Add([]byte{0x82, 0x83, 0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3})
	f.Add([]byte{0x82, 0x7e, 0xff, 0xff})
	f.Add([]byte{0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readWSFrame(bufio.NewReader(bytes.NewReader(data)))
	})
}

func FuzzParseSTUN(f *testing.F) {
	f.Add(make([]byte, 24))
	seed := make([]byte, 40)
	seed[4], seed[5], seed[6], seed[7] = 0x21, 0x12, 0xa4, 0x42
	seed[22], seed[23] = 0x00, 0x10
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseSTUN(data)
	})
}

func FuzzFecInput(f *testing.F) {
	f.Add([]byte{0x01, 0xff})
	f.Add([]byte{0x02, 0, 0, 0, 1, 0, 4, 2, 4, 0, 2, 0xaa, 0xbb})
	f.Fuzz(func(t *testing.T, data []byte) {
		d := fecDecoderFor(t, 4, 2, func([]byte) {})
		d.input(data)
	})
}

func FuzzReadFrameClear(f *testing.F) {
	f.Add([]byte{0x00, 0x03, magic, typeData, 0x41})
	f.Add([]byte{0x00, 0x02, magic, typePing})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		cf := &connFramer{r: bufio.NewReader(bytes.NewReader(data))}
		_, _, _, _, _ = cf.readFrame()
	})
}

func FuzzReadFrameCrypto(f *testing.F) {
	s, err := crypto.NewSealer(crypto.CipherChaCha, "fuzz-psk-0123456789abcdef", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0x00, 0x14, magic, typeData, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{0x00, 0x02, magic, typeData})
	f.Fuzz(func(t *testing.T, data []byte) {
		cf := &connFramer{r: bufio.NewReader(bytes.NewReader(data)), sealer: s}
		_, _, _, _, _ = cf.readFrame()
	})
}

func FuzzObfsOpen(f *testing.F) {
	s, err := crypto.NewSealer(crypto.CipherChaCha, "fuzz-psk-0123456789abcdef", false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _ = obfsOpen(s, data)
	})
}
