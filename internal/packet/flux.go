package packet

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

var fluxDportPool = []uint16{443, 3478, 19302, 5349, 8801}

var fluxStunDports = []uint16{3478, 19302, 5349}

var fluxShapeDports = map[string][]uint16{
	"quic":   {443},
	"video":  {443, 8801},
	"webrtc": {3478, 19302, 5349},
}

func shapeDports(shape string, pool []uint16) []uint16 {
	want := fluxShapeDports[shape]
	if len(want) == 0 {
		return pool
	}
	out := make([]uint16, 0, len(want))
	for _, p := range want {
		for _, q := range pool {
			if p == q {
				out = append(out, p)
				break
			}
		}
	}
	if len(out) == 0 {
		return pool
	}
	return out
}

const defaultFluxRotate = 600 * time.Second

type fluxShape struct {
	epoch     int64
	sport     uint16
	dport     uint16
	dportSTUN uint16
	ctrlPad   int
	relayIP   [4]byte
	relayPort uint16
}

func (s fluxShape) dportFor(carrier string) uint16 {
	if carrier == "stun" {
		return s.dportSTUN
	}
	return s.dport
}

func shapeCtrlPad(shape string, x byte) int {
	switch shape {
	case "quic":
		return 24 + int(x)%56
	case "video":
		return 64 + int(x)%160
	case "webrtc":
		return 8 + int(x)%48
	default:
		return 16 + int(x)%240
	}
}

func fluxEpochAt(rotate time.Duration, t time.Time) int64 {
	if rotate <= 0 {
		rotate = defaultFluxRotate
	}
	return t.UnixNano() / int64(rotate)
}

func deriveFluxShape(psk string, epoch int64, shape string) fluxShape {
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(epoch))
	kdf := hkdf.New(sha256.New, []byte(psk), eb[:], []byte("tnl-flux|v1|shape"))
	var b [16]byte
	_, _ = io.ReadFull(kdf, b[:])
	sh := fluxShape{
		epoch:     epoch,
		dport:     pickDport(b[1], shape, fluxDportPool),
		dportSTUN: pickDport(b[1], shape, fluxStunDports),
		sport:     uint16(20000 + int(binary.BigEndian.Uint16(b[2:4]))%40000),
		ctrlPad:   shapeCtrlPad(shape, b[5]),
		relayPort: uint16(20000 + int(binary.BigEndian.Uint16(b[12:14]))%40000),
	}
	sh.relayIP = publicLookingIP4(b[6:10])
	return sh
}

func pickDport(x byte, shape string, pool []uint16) uint16 {
	p := shapeDports(shape, pool)
	return p[int(x)%len(p)]
}

func publicLookingIP4(b []byte) [4]byte {
	var ip [4]byte
	copy(ip[:], b)
	ip[0] = 1 + ip[0]%223
	for _, bad := range []byte{0, 10, 127, 169, 172, 192, 198} {
		if ip[0] == bad {
			ip[0]++
		}
	}
	if ip[3] == 0 || ip[3] == 255 {
		ip[3] = 17
	}
	return ip
}

func graceShapes(psk string, epoch int64, shape string) []fluxShape {
	return []fluxShape{
		deriveFluxShape(psk, epoch-1, shape),
		deriveFluxShape(psk, epoch, shape),
		deriveFluxShape(psk, epoch+1, shape),
	}
}

func graceDports(psk string, epoch int64, shape, carrier string) map[uint16]bool {
	set := make(map[uint16]bool, 3)
	for _, sh := range graceShapes(psk, epoch, shape) {
		set[sh.dportFor(carrier)] = true
	}
	return set
}
