//go:build linux

package tun

import (
	"os"
	"testing"
)

func FuzzWriteBatch(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 40}, []byte{0x45, 0, 0, 40}, []byte{0x60})
	f.Add(seg(1, tcpACK, 40), seg(41, tcpACK, 40), seg(81, tcpACK|tcpPSH, 8))
	f.Add(seg6(1, tcpACK, 40), seg6(41, tcpACK, 40), []byte{})
	f.Add(notTCP(17, 20), notTCP(1, 20), fragment(seg(1, tcpACK, 20)))

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		f.Skip(err)
	}
	f.Cleanup(func() { null.Close() })
	d := &Device{f: null, fd: int(null.Fd()), Name: "null", gso: true}

	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		var in [][]byte
		for _, p := range [][]byte{a, b, c} {
			if len(p) > 0 && len(p) <= 4096 {
				in = append(in, append([]byte(nil), p...))
			}
		}
		if len(in) == 0 {
			return
		}
		_ = d.WriteBatch(in)
	})
}
