package packet

import (
	"log"
	"sync/atomic"
	"time"
)

// sendErrLog throttles one data-plane send-error line per carrier. Logging every occurrence buries the
// journal — a failing socket fails at packet rate — while logging none made this class of fault
// invisible: the carrier goes dark and the panel reads it as "the other end stopped answering" when the
// cause is local. Per-carrier, so on a hub node one tunnel's failure cannot hide behind another's.
type sendErrLog struct {
	last atomic.Int64 // unix nanos of the last line emitted
	n    atomic.Int64 // occurrences accumulated since then
}

const sendErrEvery = 30 * time.Second

// note records a send failure and emits at most one line per sendErrEvery. `what` names the carrier and
// path (e.g. "raw" / "flux") so a node running several tunnels stays readable.
func (s *sendErrLog) note(what string, err error) {
	if err == nil {
		return
	}
	s.n.Add(1)
	now := time.Now().UnixNano()
	prev := s.last.Load()
	if prev != 0 && now-prev < int64(sendErrEvery) {
		return
	}
	if !s.last.CompareAndSwap(prev, now) {
		return // another goroutine is emitting this round; its line covers ours
	}
	if n := s.n.Swap(0); n > 1 {
		log.Printf("%s: send failed: %v (+%d more in the last %s)", what, err, n-1, sendErrEvery)
		return
	}
	log.Printf("%s: send failed: %v", what, err)
}
