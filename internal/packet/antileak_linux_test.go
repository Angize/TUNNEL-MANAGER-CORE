package packet

import (
	"net"
	"sync"
	"time"
)

type leakRecorder struct {
	mu     sync.Mutex
	ev     []string
	delay  time.Duration
	tookTo chan struct{}
	fail   bool
}

func (r *leakRecorder) install(peer net.IP) (func(), bool) {
	r.mu.Lock()
	if r.tookTo != nil {
		close(r.tookTo)
		r.tookTo = nil
	}
	failing := r.fail
	r.mu.Unlock()
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	ip := peer.String()
	if failing {
		r.mu.Lock()
		r.ev = append(r.ev, "fail "+ip)
		r.mu.Unlock()
		return nil, false
	}
	r.mu.Lock()
	r.ev = append(r.ev, "add "+ip)
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.ev = append(r.ev, "del "+ip)
		r.mu.Unlock()
	}, true
}

func (r *leakRecorder) setFail(v bool) {
	r.mu.Lock()
	r.fail = v
	r.mu.Unlock()
}

func (r *leakRecorder) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ev...)
}

func evIndex(ev []string, want string) int {
	for i, e := range ev {
		if e == want {
			return i
		}
	}
	return -1
}
