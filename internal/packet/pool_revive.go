package packet

import (
	"sync"
	"time"
)

type reviveClock struct {
	mu   sync.Mutex
	at   time.Time
	step int
}

func (r *reviveClock) try(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	armed := !r.at.IsZero()
	if armed && now.Before(r.at) {
		return false
	}

	r.at = now.Add(time.Duration(ladderRevive[min(r.step, len(ladderRevive)-1)]) * time.Second)
	r.step++
	return armed
}

func (r *reviveClock) restart() {
	r.mu.Lock()
	r.at, r.step = time.Time{}, 0
	r.mu.Unlock()
}
