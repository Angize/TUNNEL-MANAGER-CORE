//go:build linux

package tun

import (
	"math/rand"
	"testing"
)

func narrowSum(b []byte, init uint32) uint32 {
	s := uint64(init)
	for i := 0; i+1 < len(b); i += 2 {
		s += uint64(b[i])<<8 | uint64(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint64(b[len(b)-1]) << 8
	}
	for s>>32 != 0 {
		s = s&0xffffffff + s>>32
	}
	return uint32(s)
}

func TestChecksumMatchesRFC1071(t *testing.T) {
	b := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := fold(sumBytes(b, 0)); got != 0xddf2 {
		t.Fatalf("folded sum = %#04x, RFC 1071 says 0xddf2", got)
	}
	if got := ^fold(sumBytes(b, 0)); got != 0x220d {
		t.Fatalf("checksum = %#04x, RFC 1071 says 0x220d", got)
	}
}

func TestChecksumAgreesWithTheNarrowSum(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	lens := []int{}
	for n := 0; n <= 300; n++ {
		lens = append(lens, n)
	}
	lens = append(lens, 1400, 1401, 1500, 9000, 65535)

	for _, n := range lens {
		b := make([]byte, n)
		r.Read(b)
		for _, init := range []uint32{0, 1, 0xffff, 0x10000, 0xffff0000, 0xfffffffe} {
			want, got := fold(narrowSum(b, init)), fold(sumBytes(b, init))
			if want != got {
				t.Fatalf("len %d init %#x: wide sum folds to %#04x, narrow to %#04x", n, init, got, want)
			}
		}
	}
}

func TestChecksumCarriesOnAllOnes(t *testing.T) {
	for n := 0; n <= 64; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = 0xff
		}
		if want, got := fold(narrowSum(b, 0xffff)), fold(sumBytes(b, 0xffff)); want != got {
			t.Fatalf("%d bytes of 0xff: wide %#04x, narrow %#04x", n, got, want)
		}
	}
}

func TestChecksumPadsTheOddByteHigh(t *testing.T) {
	if got, want := fold(sumBytes([]byte{0xab}, 0)), uint16(0xab00); got != want {
		t.Fatalf("a lone 0xab summed to %#04x, want %#04x", got, want)
	}
	if got, want := fold(sumBytes([]byte{0x00, 0x00, 0xab}, 0)), uint16(0xab00); got != want {
		t.Fatalf("a trailing 0xab summed to %#04x, want %#04x", got, want)
	}
}

func FuzzChecksum(f *testing.F) {
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0xab}, uint32(0xffff))
	f.Add([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}, uint32(0))
	f.Fuzz(func(t *testing.T, b []byte, init uint32) {
		if want, got := fold(narrowSum(b, init)), fold(sumBytes(b, init)); want != got {
			t.Fatalf("len %d init %#x: wide %#04x, narrow %#04x", len(b), init, got, want)
		}
	})
}

func BenchmarkChecksum(b *testing.B) {
	buf := make([]byte, 1400)
	rand.New(rand.NewSource(1)).Read(buf)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		sumBytes(buf, 0)
	}
}

func BenchmarkChecksumNarrow(b *testing.B) {
	buf := make([]byte, 1400)
	rand.New(rand.NewSource(1)).Read(buf)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		narrowSum(buf, 0)
	}
}
