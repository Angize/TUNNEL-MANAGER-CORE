//go:build linux

package packet

import "crypto/rand"

type desyncCfg struct {
	on    bool
	ttl   int
	count int
	mode  string
}

func newDesyncCfg(on bool, ttl, count int, mode string) desyncCfg {
	if !on {
		return desyncCfg{}
	}
	if ttl <= 0 {
		ttl = 4
	}
	if count <= 0 {
		count = 2
	}
	switch mode {
	case "ttl", "badsum", "both":
	default:
		mode = "ttl"
	}
	return desyncCfg{on: true, ttl: ttl, count: count, mode: mode}
}

func (d desyncCfg) usesBadsum() bool { return d.on && (d.mode == "badsum" || d.mode == "both") }

func (d desyncCfg) usesLowTTL() bool { return d.on && (d.mode == "ttl" || d.mode == "both") }

type fakeSpec struct {
	ttl    int
	badSum bool
}

func (d desyncCfg) specs() []fakeSpec {
	if !d.on {
		return nil
	}
	out := make([]fakeSpec, 0, d.count)
	for i := 0; i < d.count; i++ {
		bad := d.mode == "badsum" || (d.mode == "both" && i%2 == 1)
		ttl := d.ttl
		if bad {
			ttl = 64
		}
		out = append(out, fakeSpec{ttl: ttl, badSum: bad})
	}
	return out
}

func (d desyncCfg) specsTCP() []fakeSpec {
	if !d.on {
		return nil
	}
	ttl := d.ttl
	if ttl > injectMaxTTL {
		ttl = injectMaxTTL
	}
	out := make([]fakeSpec, 0, d.count)
	for i := 0; i < d.count; i++ {
		bad := d.mode == "badsum" || (d.mode == "both" && i%2 == 1)
		out = append(out, fakeSpec{ttl: ttl, badSum: bad})
	}
	return out
}

const fakeSeqGap = 1<<20 + 1<<15

func fakePayload() []byte {
	var lb [1]byte
	_, _ = rand.Read(lb[:])
	n := 48 + int(lb[0])%64
	p := make([]byte, n)
	_, _ = rand.Read(p)
	return p
}
