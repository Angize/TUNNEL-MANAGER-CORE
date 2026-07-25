package packet

import (
	"log"
	"sync/atomic"
	"time"
)

// sendErrLog throttles one data-plane send-error line per carrier.
//
// Both extremes are wrong here. Logging every occurrence buries the journal — a failing socket fails at
// packet rate, so a stalled tunnel would write thousands of identical lines a second. Logging none is
// what made this whole class of fault invisible: the carrier goes dark, the peer's heartbeat freezes,
// and the panel renders it as "the other end stopped answering" — pointing the operator at the remote
// node when the failure is local (ENOBUFS on a burst, ENETUNREACH after a route flap, EMSGSIZE after an
// MTU change, EPERM when CAP_NET_RAW is lost, EINVAL when a pinned source is no longer a local address).
//
// One line per interval carrying the suppressed count gives the cause without the flood. Per-carrier
// rather than package-level on purpose: on a hub node with many tunnels, a shared throttle would let one
// noisy tunnel hide another's failure entirely.
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
