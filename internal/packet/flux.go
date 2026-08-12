// Package-level flux shape derivation, kept platform-independent (and therefore
// unit-testable) apart from the socket work in flux_linux.go.
//
// flux is a polymorphic, moving-target carrier. Unlike the fixed raw profiles
// (bare/ipip/gre/... each pinned to one IP protocol number), flux derives its
// carrier *shape* from the pre-shared key and a time-based epoch, and both ends
// recompute it independently from the wall clock — so the shape rotates in
// lock-step with NO negotiation packet on the wire to fingerprint or to signal a
// rotation. The decode is shape-INDEPENDENT (the sealed frame is identical
// regardless of the carrier), which is what makes a rotation free: it changes
// only how packets look, never how they are opened, so no re-handshake is needed.
//
// This file derives, for a given epoch:
//   - sport/dport: the UDP 4-tuple the carrier rides this epoch
//   - padMax:      the per-frame random padding budget (coarse size shaping)
//
// The receiver cannot bind a single UDP port (the destination port moves), so
// flux_linux.go sends via IP_HDRINCL (which also lets it rotate the source port
// without rebinding) and receives via AF_PACKET, filtering to the small set of
// ports that the current, previous, and next epochs derive (the grace window
// that absorbs clock skew and in-flight packets across a rotation boundary).
package packet

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// fluxDportPool is the set of UDP destination ports the "udp" flux carrier rotates
// through. Every entry is a universally-passed QUIC/STUN/WebRTC media port, so the
// flow looks like ordinary real-time UDP to any transit while the 4-tuple still
// moves each epoch (a moving target with no odd port to flag). The source port is
// drawn from the ephemeral range, which is exactly what a real client would use.
var fluxDportPool = []uint16{443, 3478, 19302, 5349, 8801}

// fluxStunDports is the destination-port pool for the "stun" carrier — STUN/TURN
// ports only, since that carrier additionally wraps each frame in a real STUN
// Binding header so the flow parses as WebRTC signalling, not just generic UDP.
var fluxStunDports = []uint16{3478, 19302, 5349}

// defaultFluxRotate is the LAST-RESORT epoch length for fluxEpochAt, so a non-positive rotate cannot
// divide by zero. It is not a tuning knob and not the value a real tunnel runs on: config.applyDefaults
// resolves flux_rotate_secs to a concrete number (600 when omitted) before any carrier is built, and the
// panel always sends one explicitly — both ends must compute the SAME epoch from the clock alone, so the
// value has to be in the config rather than in each side's defaults. Ten minutes trades rotation agility
// against how often the (cheap) statistical shape churns; "rotate now" bumps the epoch out of band.
const defaultFluxRotate = 600 * time.Second

// fluxShape is the per-epoch carrier descriptor. It is a pure function of
// (PSK, epoch, shapeProfile): both ends derive the same one from the clock alone.
// Both carriers ride sport plus a carrier-specific destination port.
type fluxShape struct {
	epoch     int64
	sport     uint16 // rotating source port (ephemeral range)
	dport     uint16 // udp carrier: rotating destination port (from fluxDportPool)
	dportSTUN uint16 // stun carrier: rotating destination port (STUN/TURN ports only)
	ctrlPad   int    // control-frame (ping/pong) padding budget — the shape profile's size signature
}

// dportFor returns the destination port to use for the given carrier this epoch.
func (s fluxShape) dportFor(carrier string) uint16 {
	if carrier == "stun" {
		return s.dportSTUN
	}
	return s.dport
}

// shapeCtrlPad maps a statistical shape profile to the padding budget for tiny
// control frames (keepalives), which are otherwise the most fingerprintable
// fixed-size packets. Data frames stay near the MTU and are already varied, so the
// profile shapes the SMALL-packet size histogram to resemble the mimicked traffic:
// webrtc → small RTP-ish, quic → short-ack-ish, video → larger bursts. This is
// coarse size-shaping (no added latency, no MTU cost), not full statistical mimicry.
func shapeCtrlPad(shape string, x byte) int {
	switch shape {
	case "quic":
		return 24 + int(x)%56 // 24..79
	case "video":
		return 64 + int(x)%160 // 64..223 — larger, bursty
	case "webrtc":
		return 8 + int(x)%48 // 8..55 — small RTP-ish
	default: // "random"
		return 16 + int(x)%240 // 16..255 (matches the control padding budget)
	}
}

// fluxEpochAt returns the epoch index for time t under the given rotation period.
// epoch = floor(unixNanos / rotateNanos); a non-positive rotate falls back to the
// default so a misconfigured link still rotates rather than dividing by zero.
func fluxEpochAt(rotate time.Duration, t time.Time) int64 {
	if rotate <= 0 {
		rotate = defaultFluxRotate
	}
	return t.UnixNano() / int64(rotate)
}

// deriveFluxShape expands (PSK, epoch, shapeProfile) into the epoch's carrier shape
// via HKDF, domain-separated from the session-key KDF so the two never derive the
// same bytes. shape is the statistical profile ("quic"/"video"/"webrtc"/"random").
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
		sport:     uint16(20000 + int(binary.BigEndian.Uint16(b[2:4]))%40000), // 20000..59999
		ctrlPad:   shapeCtrlPad(shape, b[5]),
	}
}

// graceShapes returns the shapes acceptable around the given center epoch: those
// derived for the previous, current, and next epoch. Accepting the neighbours
// absorbs modest clock skew between the ends and any packet in flight when the
// epoch ticked, so traffic never drops at a rotation boundary even though neither
// side sends a rotation signal. The AEAD still authenticates every frame, so
// widening the carrier filter never weakens security. The center epoch already
// includes any manual epoch offset (see Flux.epochNow).
func graceShapes(psk string, epoch int64, shape string) []fluxShape {
	return []fluxShape{
		deriveFluxShape(psk, epoch-1, shape),
		deriveFluxShape(psk, epoch, shape),
		deriveFluxShape(psk, epoch+1, shape),
	}
}

// graceDports is the wire view of graceShapes: the acceptable UDP destination
// ports for the given carrier.
func graceDports(psk string, epoch int64, shape, carrier string) map[uint16]bool {
	set := make(map[uint16]bool, 3)
	for _, sh := range graceShapes(psk, epoch, shape) {
		set[sh.dportFor(carrier)] = true
	}
	return set
}
