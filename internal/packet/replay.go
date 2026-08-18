package packet

const replayWindow = 64

const MaxFecData = replayWindow

type replayGuard struct {
	haveSession bool
	session     uint64
	top         uint64
	bits        uint64
}

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
		return false
	}
	mask := uint64(1) << offset
	if g.bits&mask != 0 {
		return false
	}
	g.bits |= mask
	return true
}
