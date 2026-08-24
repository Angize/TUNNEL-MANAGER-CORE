package packet

import (
	"net"
	"strconv"
	"sync"
	"time"
)

type pathKey struct {
	Src   string `json:"src"`
	Sport uint16 `json:"sport"`
	Dst   string `json:"dst"`
	Dport uint16 `json:"dport"`
	SNI   string `json:"sni,omitempty"`
}

func addrParts(a net.Addr) (host string, port uint16) {
	if a == nil {
		return "", 0
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return "", 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return h, 0
	}
	return h, uint16(n)
}

type pathTracker struct {
	// One sampler at a time. live() runs with mu released -- taking it there would mean holding this
	// lock across the carrier's own -- so without this two samplers can commit their observations in
	// the opposite order to the one they took them in, and the tracker publishes a path older than one
	// it has already published, with a fresh epoch on it. Every event site calls write(), which samples.
	sampleMu sync.Mutex

	mu    sync.Mutex
	cur   pathKey
	epoch int64
	ready bool

	live func() (pathKey, bool)
}

func (t *pathTracker) setLive(live func() (pathKey, bool)) {
	t.mu.Lock()
	t.live = live
	t.mu.Unlock()
}

func (t *pathTracker) sample() (changed bool) {
	t.sampleMu.Lock()
	defer t.sampleMu.Unlock()
	t.mu.Lock()
	live := t.live
	t.mu.Unlock()
	if live == nil {
		return false
	}
	return t.observe(live())
}

func samplePathLoop(t *pathTracker, flush func(), closeCh <-chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-tick.C:
			if t.sample() {
				flush()
			}
		}
	}
}

func (t *pathTracker) observe(k pathKey, ready bool) (changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if k.Dst == "" {
		changed, t.ready = t.ready, false
		return changed
	}
	if k != t.cur {
		t.cur, t.epoch, changed = k, t.epoch+1, true
	}
	if ready != t.ready {
		t.ready, changed = ready, true
	}
	return changed
}

// A new session on the same endpoints is still a new session, and the tuple cannot say so: an http or
// grpc carrier has no local address to put in its path at all -- src is "" and sport is 0 -- so a
// reconnect to the same edge under the same domain is byte-identical to the session before it and the
// epoch never moves. That epoch is the ONLY thing keeping a verdict measured on one session from
// being charged to the next, and on those tunnels it was inert: the probe ran while the carrier was
// down, the pair was read after it came back somewhere else, and the endpoint that had just returned
// took the burn.
func (t *pathTracker) freshen() {
	t.mu.Lock()
	t.cur = pathKey{}
	t.mu.Unlock()
}

func (t *pathTracker) snapshot() (epoch int64, k pathKey, ready bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.epoch, t.cur, t.ready
}
