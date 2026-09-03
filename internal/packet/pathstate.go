package packet

import (
	"net"
	"strconv"
	"sync"
	"time"
)

type rotStatus struct {
	Sport  uint16 `json:"sport"`
	Dport  uint16 `json:"dport"`
	Dports int    `json:"dports"`
	Every  int    `json:"every"`
	Lo     uint16 `json:"lo"`
	Hi     uint16 `json:"hi"`
	Drawn  uint64 `json:"drawn"`
}

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
