package packet

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// pathKey identifies the network path a client tunnel is CURRENTLY riding: the tuple it puts on the
// wire, plus the SNI for the carriers that present one. A liveness verdict is only ever about one of
// these — measured on this path it says nothing about the next, which is why the node stamps its
// verdict with the epoch below and this side refuses a stale one.
//
// Every field is read from the carrier's LIVE send state, never from a pool's cursor. The two
// diverge by design — a make-before-break rotation advances the cursor while the connection stays
// put, and a pin moves it before any dial — so sampling the cursor would spend epochs on moves that
// never happened and miss the ones that did.
//
// The IP protocol number is deliberately absent: it comes from the raw profile in the config and
// nothing rotates it, so a field for it could never differ between two samples.
type pathKey struct {
	Src   string `json:"src"`
	Sport uint16 `json:"sport"`
	Dst   string `json:"dst"`
	Dport uint16 `json:"dport"`
	SNI   string `json:"sni,omitempty"`
}

// addrParts splits a net.Addr into the host and port a pathKey carries — for the addresses that
// arrive as the INTERFACE and have to be recovered from it. A carrier holding a concrete *net.UDPAddr
// already has both parts and reads them directly.
//
// It goes through the string form rather than a type assertion because the stream carriers hand back
// a wrapped conn (TLS, then ws), and an assertion that quietly failed would leave the path unnamed —
// which reads downstream as a tunnel nothing may judge.
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

// pathTracker turns SAMPLED pathKeys into a monotonic epoch. It is never told that the path moved.
//
// Being told would mean a bump at every site that moves it — both rotations, both pins, the port
// roll, every re-dial, both ws axes — and the site that forgets is a path that changed while the
// epoch stood still, which is the exact silence the epoch exists to expose. Sampling has one place
// to be right, and it catches a mover that announced nothing.
type pathTracker struct {
	mu    sync.Mutex
	cur   pathKey
	epoch int64
	ready bool
	// live is the carrier's own report of what it is sending on. Installed once at setup; nil on a
	// carrier that has no path to name (dns rides a resolver list, not a tuple).
	live func() (pathKey, bool)
}

// setLive installs the carrier's report. Under the lock because the sampler may already be running:
// the writers publish before a carrier finishes wiring itself.
func (t *pathTracker) setLive(live func() (pathKey, bool)) {
	t.mu.Lock()
	t.live = live
	t.mu.Unlock()
}

// sample reads the carrier's live path and reports whether the published snapshot changed. Called
// from the status writers, which every deliberate mover already reaches, and from samplePathLoop for
// everything that changes without publishing — a mover that announces nothing, and a session coming
// up, which moves no address at all.
func (t *pathTracker) sample() (changed bool) {
	t.mu.Lock()
	live := t.live
	t.mu.Unlock()
	if live == nil {
		return false
	}
	return t.observe(live())
}

// samplePathLoop is the net under the status writers: anything that changes what a reader must see —
// a path that moved with nobody publishing it, or a session that came up and moved no address — is
// caught within a tick and flushed. It exists because "every change publishes" is a property of
// today's code, not something a reader may depend on.
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

// observe records the live path and reports whether the PUBLISHED snapshot changed — which is the
// flush condition, not "the path moved". A session coming up changes no address, and a reader that
// never sees `ready` turn true never judges the tunnel at all.
//
// The epoch is the narrower thing: it steps only when the path itself differs, because that is what a
// verdict is keyed on. An empty destination is "not resolved yet" — mid-rebind, or no peer learned —
// so it spends no epoch, but it does clear ready: whatever the carrier last said, it is not carrying
// on a path it cannot name.
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

// snapshot is what the status writers publish: the epoch a verdict must carry to be accepted, the
// path it names, and whether a session is up on it (a verdict measured before that is about the
// re-handshake, not the path).
func (t *pathTracker) snapshot() (epoch int64, k pathKey, ready bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.epoch, t.cur, t.ready
}
