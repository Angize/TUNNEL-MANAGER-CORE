// This file implements anti-replay protection for the core carriers. Every crypto-sealed frame carries
// an authenticated (session, seq) pair in its nonce: seq strictly increases within a sender's process,
// and session changes when it restarts. A receiver rejects any seq it has seen or that is too old. The
// window is the IPsec-style sliding bitmap of the last 64 seqs, reset when the peer's session id changes.
package packet

const replayWindow = 64

// MaxFecData is the largest fec_data the receiver can actually repair, and it is this window. The FEC
// decoder delivers intact shards on ARRIVAL and parity-recovered ones LAST, so a recovered frame reaches
// the AEAD up to blocksize-1 seqs behind the newest already delivered, and anything replayWindow or more
// behind is refused. Past this size FEC costs its full bandwidth and repairs nothing, in silence.
const MaxFecData = replayWindow

// replayGuard tracks the highest sequence accepted for the current peer session plus a bitmap of the
// preceding replayWindow-1 sequences. The mutex-free design relies on ok() never being called from two
// goroutines at once; each core carrier drives it from exactly one reader goroutine.
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
