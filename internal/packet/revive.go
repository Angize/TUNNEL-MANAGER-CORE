package packet

import (
	"sync"
	"time"
)

// When the ladder has spent every rung and the walk found nowhere to go, the climb is over: nothing
// redraws the source port and nothing hands out another handshake. There is no way back from that --
// only a probe that finds traffic crossing refills the rungs, and on a path whose one fault is the port
// it last drew, no traffic ever crosses to say so.
//
// This is the way back. Each dead end arms the next attempt one step further into ladderRevive, so a
// tunnel that needed one more draw gets it in seconds while one that is truly gone backs off instead of
// churning.
type reviveClock struct {
	mu   sync.Mutex
	at   time.Time
	step int
}

// Spend this dead end: report whether the ladder may refill now, and arm the next wait either way.
// Named for what it does to the clock, like the rungs beside it -- the FIRST dead end only arms, because
// the rungs were spent on the way here and there is nothing yet to give back.
func (r *reviveClock) try(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	armed := !r.at.IsZero()
	if armed && now.Before(r.at) {
		return false
	}
	// Clamped HERE and nowhere else: a step counter bounded on the way in as well would make this read
	// unreachable, and the two rules would then have to be kept in agreement by hand.
	r.at = now.Add(time.Duration(ladderRevive[min(r.step, len(ladderRevive)-1)]) * time.Second)
	r.step++
	return armed
}

func (r *reviveClock) restart() {
	r.mu.Lock()
	r.at, r.step = time.Time{}, 0
	r.mu.Unlock()
}
