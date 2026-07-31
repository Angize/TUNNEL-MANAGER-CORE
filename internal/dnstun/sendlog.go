package dnstun

import (
	"log"
	"sync/atomic"
	"time"
)

// sendErrLog throttles a send-error line to at most one per interval, carrying the suppressed count.
//
// A resolver we cannot write to fails at query rate, so logging every occurrence would bury the journal;
// logging none is what made the fault invisible — the operator saw only "dns session: handshake timed
// out", which reads as censorship and sends diagnosis toward the network when the cause is local (an
// unroutable resolver entry, an egress REJECT, a source address that disappeared).
//
// Deliberately duplicated from internal/packet's copy rather than shared: the two packages have no
// dependency on each other today, and a shared logging package is not worth creating for ten lines.
type sendErrLog struct {
	last atomic.Int64 // unix nanos of the last line emitted
	n    atomic.Int64 // occurrences accumulated since then
}

const sendErrEvery = 30 * time.Second

func (s *sendErrLog) note(what string, err error) { s.noteAs(what, "send failed", err) }

// noteAs is note with the caller's own description of the fault, for one that is not a send. A resolver
// ANSWERING with SERVFAIL/REFUSED has the same shape — it recurs at query rate, and with nothing said
// the only symptom is a tunnel that goes quiet, which reads as censorship — but "send failed" would
// point the operator at the wrong end of the path.
func (s *sendErrLog) noteAs(what, doing string, err error) {
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
		log.Printf("%s: %s: %v (+%d more in the last %s)", what, doing, err, n-1, sendErrEvery)
		return
	}
	log.Printf("%s: %s: %v", what, doing, err)
}
