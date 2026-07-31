// This file implements anti-replay protection for the core carriers. Every
// crypto-sealed frame carries an authenticated (session, seq) pair in its nonce
// (see crypto.Sealer): seq strictly increases within a sender's process and
// session changes when the sender restarts. A receiver rejects any frame whose
// seq it has already seen (or that is too old to track), which stops an attacker
// from capturing a valid frame and replaying it — the attack that would
// otherwise let a captured datagram rebind the UDP peer or re-inject a packet.
//
// The window is the standard IPsec-style sliding bitmap of the last 64 sequence
// numbers. It resets when the peer's session id changes, which is what lets a
// legitimately restarted peer (new random prefix, counter back to 1) reconnect.
package packet

const replayWindow = 64

// MaxFecData is the largest fec_data the receiver can actually repair, and it is this window.
//
// The FEC decoder delivers intact data shards on ARRIVAL and parity-recovered ones LAST (that is what
// makes a block that never completes cost only its lost shards instead of all of them). So a
// recovered frame reaches the AEAD up to blocksize-1 sequence numbers behind the newest one already
// delivered — and anything replayWindow or more behind is refused here as "too old to prove it is not
// a replay". Past this size the parity is computed, transmitted and reconstructed, and then thrown
// away by the replay guard: FEC costs its full bandwidth and repairs nothing, in silence.
//
// MEASURED, not reasoned: fec_data 63 and 64 recover, 65 and above are refused.
//
// ⚠ AT the bound there is no slack, and that is deliberate rather than overlooked. Keepalives ride the
// same stream as fecTypePass frames, which the decoder hands straight to deliver(), so one landing
// between a block's first shard and its recovery advances `top` by one more and pushes a fec_data=64
// recovery exactly onto the edge. The cost is ONE recovered frame, on the order of a 15 ms block
// window against a 15 s keepalive interval — nothing like the total, permanent loss above the bound,
// which is what this constant exists to prevent. Subtracting a margin would be inventing a number
// (why one keepalive and not two?), so the bound stays at the point where FEC stops working at all.
//
// The bound lives HERE, beside the window it comes from, so the two cannot drift apart.
const MaxFecData = replayWindow

// replayGuard tracks the highest sequence accepted for the current peer session
// plus a bitmap of the preceding replayWindow-1 sequences. It is safe for
// concurrent use by a single receive loop (the only caller), but the mutex-free
// design relies on ok() not being called from two goroutines at once; the core
// carriers each drive it from exactly one reader goroutine.
type replayGuard struct {
	haveSession bool
	session     uint64
	top         uint64 // highest seq accepted so far
	bits        uint64 // bit i set => seq (top-i) already seen
}

// ok reports whether a frame with the given (session, seq) is fresh, and records
// it. A new session id adopts and resets the window (peer restart / first
// frame). Duplicates and frames older than the window are rejected.
func (g *replayGuard) ok(session, seq uint64) bool {
	if !g.haveSession || session != g.session {
		g.haveSession = true
		g.session = session
		g.top = seq
		g.bits = 1
		return true
	}
	if seq > g.top {
		shift := seq - g.top
		if shift >= replayWindow {
			g.bits = 1
		} else {
			g.bits = (g.bits << shift) | 1
		}
		g.top = seq
		return true
	}
	offset := g.top - seq
	if offset >= replayWindow {
		return false // too old to prove it is not a replay
	}
	mask := uint64(1) << offset
	if g.bits&mask != 0 {
		return false // already seen
	}
	g.bits |= mask
	return true
}
