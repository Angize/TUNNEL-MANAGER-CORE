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

const defaultFluxRotate = 600 * time.Second

type fluxShape struct {
	epoch     int64
	sport     uint16
	dport     uint16
	dportSTUN uint16
	ctrlPad   int
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
	return fluxShape{
		epoch:     epoch,
		dport:     fluxDportPool[int(b[1])%len(fluxDportPool)],
		dportSTUN: fluxStunDports[int(b[1])%len(fluxStunDports)],
		sport:     uint16(20000 + int(binary.BigEndian.Uint16(b[2:4]))%40000),
		ctrlPad:   shapeCtrlPad(shape, b[5]),
	}
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
