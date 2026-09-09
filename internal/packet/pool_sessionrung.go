package packet

import "sync"

type sessionRung struct {
	mu sync.Mutex

	drop  func() bool
	spent bool
}

func (s *sessionRung) setDrop(drop func() bool) {
	s.mu.Lock()
	s.drop = drop
	s.mu.Unlock()
}

func (s *sessionRung) try() bool {
	s.mu.Lock()
	drop := s.drop
	if drop == nil || s.spent {
		s.mu.Unlock()
		return false
	}
	s.spent = true
	s.mu.Unlock()

	if drop() {
		return true
	}
	s.mu.Lock()
	s.spent = false
	s.mu.Unlock()
	return false
}

func (s *sessionRung) restart() {
	s.mu.Lock()
	s.spent = false
	s.mu.Unlock()
}
