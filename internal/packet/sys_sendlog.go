package packet

import (
	"log"
	"sync/atomic"
	"time"
)

type sendErrLog struct {
	last atomic.Int64
	n    atomic.Int64
}

const sendErrEvery = 30 * time.Second

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
		return
	}
	if n := s.n.Swap(0); n > 1 {
		log.Printf("%s: send failed: %v (+%d more in the last %s)", what, err, n-1, sendErrEvery)
		return
	}
	log.Printf("%s: send failed: %v", what, err)
}
