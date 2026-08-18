package packet

import "sync"

// sessionRung is the ladder's second free step: give up the session and handshake again, once, before
// anything is condemned.
//
// It is here because a peer that restarted makes a perfectly good path carry nothing. Every frame the
// client sends is answered by a server that cannot open it, so the probe measures silence and the walk
// answers by burning a healthy destination — for a fault that lives in neither endpoint. One round trip
// settles it, and it moves the tunnel nowhere, so it costs a round of the outage and nothing else.
//
// ONCE per outage, unlike the port draws. A second handshake to the same peer asks a question the
// first already answered; if the first did not bring the tunnel back, the session was not what was
// wrong.
//
// It is also the ONLY thing that re-handshakes: no carrier gives its session up on a clock any more.
// Every client has a verdict mailbox, so the step runs on the judge's evidence — which measures where
// the payload travels — rather than on a timer measuring our own keepalives coming back.
type sessionRung struct {
	mu sync.Mutex
	// drop tears down the session so the client loop re-handshakes, and reports whether there was one
	// to tear down. nil on a carrier whose session is its connection — those re-dial rather than
	// re-handshake, which is a different step with a different cost.
	drop  func() bool
	spent bool
}

// setDrop installs the carrier's teardown. A carrier that never calls this has no rung one.
func (s *sessionRung) setDrop(drop func() bool) {
	s.mu.Lock()
	s.drop = drop
	s.mu.Unlock()
}

// try spends the step if it is still available, and reports whether the ladder should stop here.
//
// The step is TAKEN before the teardown runs and handed back if there was no session to tear down,
// for the reason portRung.try gives: checking and spending in two separate holds lets two callers
// both find it open.
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
	s.mu.Lock() // no session existed: the handshake is already running, so this was not a step
	s.spent = false
	s.mu.Unlock()
	return false
}

// restart makes the step available again. Traffic crossing settles what it was asking, so the next
// outage gets its own.
func (s *sessionRung) restart() {
	s.mu.Lock()
	s.spent = false
	s.mu.Unlock()
}
