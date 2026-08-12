package packet

import (
	"net"
	"sync"
	"time"
)

// leakRecorder stands in for the real iptables installer (addFluxDrop / addRawDrop): it records
// every install and every removal, in order, and can be made slow so a caller that waits for
// iptables is visible as elapsed time. Nothing here reaches the host firewall.
type leakRecorder struct {
	mu     sync.Mutex
	ev     []string
	delay  time.Duration
	tookTo chan struct{}
	fail   bool // the next install reports the rules did NOT go in, as a contended iptables does
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

// setFail switches the recorder between installing and reporting failure.
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
