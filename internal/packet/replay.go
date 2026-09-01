package packet

import (
	"log"
	"sync/atomic"
	"time"
)

const replayWindow = 2048

const replayWords = replayWindow / 64

const MaxFecData = 64

type replayGuard struct {
	haveSession bool
	session     uint64
	top         uint64
	bits        [replayWords]uint64
}

func (g *replayGuard) mark(seq uint64, on bool) {
	i, b := seq%replayWindow/64, uint64(1)<<(seq%64)
	if on {
		g.bits[i] |= b
		return
	}
	g.bits[i] &^= b
}

func (g *replayGuard) seen(seq uint64) bool {
	return g.bits[seq%replayWindow/64]&(uint64(1)<<(seq%64)) != 0
}

func (g *replayGuard) open(session, seq uint64) bool {
	g.haveSession, g.session, g.top = true, session, seq
	g.bits = [replayWords]uint64{}
	g.mark(seq, true)
	return true
}

func (g *replayGuard) ok(session, seq uint64) bool {
	if !g.haveSession || session != g.session {
		return g.open(session, seq)
	}
	if seq > g.top {
		if seq-g.top >= replayWindow {
			return g.open(session, seq)
		}
		for s := g.top + 1; s < seq; s++ {
			g.mark(s, false)
		}
		g.top = seq
		g.mark(seq, true)
		return true
	}
	offset := g.top - seq
	if offset >= replayWindow {
		replayDrops.note(offset)
		return false
	}
	if g.seen(seq) {
		replayDrops.note(offset)
		return false
	}
	g.mark(seq, true)
	return true
}

const replayDropEvery = 30 * time.Second

type replayDropLog struct {
	last  atomic.Int64
	n     atomic.Int64
	worst atomic.Uint64
}

var replayDrops replayDropLog

func (r *replayDropLog) note(offset uint64) {
	r.n.Add(1)
	for {
		w := r.worst.Load()
		if offset <= w || r.worst.CompareAndSwap(w, offset) {
			break
		}
	}
	now := time.Now().UnixNano()
	prev := r.last.Load()
	if prev != 0 && now-prev < int64(replayDropEvery) {
		return
	}
	if !r.last.CompareAndSwap(prev, now) {
		return
	}
	n, worst := r.n.Swap(0), r.worst.Swap(0)
	log.Printf("core: %d authenticated frames discarded by the replay guard in the last %s, the "+
		"furthest %d behind the newest (the window is %d). Either a peer is replaying, or this build "+
		"reorders its own frames further than the window covers -- lower workers if it is the latter",
		n, replayDropEvery, worst, replayWindow)
}
