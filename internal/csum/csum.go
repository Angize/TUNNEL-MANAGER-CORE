package csum

import (
	"encoding/binary"
	"math/bits"
)

func Add(b []byte, acc uint64) uint64 {
	var c uint64
	for len(b) >= 32 {
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b), c)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[8:]), c)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[16:]), c)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b[24:]), c)
		b = b[32:]
	}
	for len(b) >= 8 {
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(b), c)
		b = b[8:]
	}
	if len(b) > 0 {
		var t [8]byte
		copy(t[:], b)
		acc, c = bits.Add64(acc, binary.BigEndian.Uint64(t[:]), c)
	}
	return acc + c
}

func Fold(acc uint64) uint16 {
	for acc>>16 != 0 {
		acc = (acc >> 16) + (acc & 0xffff)
	}
	return uint16(acc)
}
