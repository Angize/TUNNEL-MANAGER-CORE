package packet

// Out-of-band destination probing for the DIRECT carriers' rotation pool. The ws edge pool has had this
// since it was written (probeEdgeFull / dueRetests / retestLoop, ws_pool.go + tcp.go); the direct pool
// never did, so the only way a burned endpoint could be retested was to point the LIVE data plane at it
// and see whether a frame came back — which moves the tunnel to answer a question about an endpoint it
// is not on. Here a due endpoint is tested by a real PSK-authenticated handshake INIT that touches no
// session, no peer pointer and no clock: the answer decides re-admission, the live carrier does not move.

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

// destProbeTries is how many INITs one probe sends before calling the endpoint unreachable. A datagram
// carrier loses packets, so a single unanswered INIT is not evidence; the gap between them is the live
// path's own jittered handshake retransmit (a fixed 1 Hz beacon would be a shape to lock onto).
const destProbeTries = 3

// destProbeWait is one in-flight probe: the endpoint under test and the predicate that recognises its
// answer. The carrier's receive path offers frames it could not otherwise place; the first match ends it.
type destProbeWait struct {
	ip    net.IP
	match func(body []byte) bool
	done  chan struct{}
	once  sync.Once
}

// destProbe holds a datagram carrier's single in-flight destination probe. The zero value is "nothing
// pending", and every method is safe to call from the receive goroutine. TCP needs none of this — its
// probe owns a whole connection and reads the answer itself.
type destProbe struct {
	cur atomic.Pointer[destProbeWait]
}

// answered is the receive-path hook: true when body is the pending probe's answer from ip, in which
// case the frame belongs to the probe and the carrier must not process it further. One atomic load
// when nothing is pending, which is all but always.
func (d *destProbe) answered(ip net.IP, body []byte) bool {
	w := d.cur.Load()
	if w == nil || !w.ip.Equal(ip) || !w.match(body) {
		return false
	}
	w.once.Do(func() { close(w.done) })
	return true
}

// run arms the probe, sends through the carrier's send func destProbeTries times (stopping as soon as
// the answer arrives), and reports whether it was answered. Only one probe is in flight at a time —
// runDestRetests walks its batch sequentially — so a single slot is enough.
func (d *destProbe) run(ip net.IP, match func(body []byte) bool, send func()) bool {
	w := &destProbeWait{ip: ip, match: match, done: make(chan struct{})}
	d.cur.Store(w)
	defer d.cur.Store(nil)
	for i := 0; i < destProbeTries; i++ {
		send()
		select {
		case <-w.done:
			return true
		case <-time.After(handshakeRetransmitWait()):
		}
	}
	select {
	case <-w.done:
		return true
	default:
		return false
	}
}

// probeDestHandshake is the crypto-mode destination probe shared by udp/raw/flux: a REAL init built on
// a throwaway ephemeral, answered only by a peer that holds the PSK. The carrier's own control-send
// func carries it, so the probe leaves in exactly the shape the live path uses (profile wrap, epoch
// shape, FEC passthrough tag) — a probe the censor could tell apart from the carrier proves nothing.
func probeDestHandshake(d *destProbe, psk string, ip net.IP, send func(init []byte)) bool {
	eph, err := crypto.GenerateEphemeral()
	if err != nil {
		return false
	}
	init := crypto.InitMsg(psk, eph)
	match := func(body []byte) bool {
		_, perr := crypto.ParseResp(psk, eph.Pub, body)
		return perr == nil
	}
	return d.run(ip, match, func() { send(init) })
}

// runDestRetests is the direct pool's retest scheduler: every second it hands each endpoint whose
// backoff has elapsed to the carrier's out-of-band probe and feeds the verdict back into the health
// FSM, emitting one heal event per recovery. The batch runs OFF the tick, one at a time, so probes
// never pile up on a struggling endpoint. Runs until closeCh. Mirrors the ws pool's retestLoop.
func runDestRetests(pp *PeerPool, closeCh <-chan struct{}, probe func(addr string) bool,
	ev func(kind, code, detail string)) {
	if pp == nil {
		return
	}
	// From here on re-admission is ours, and a returning frame stops clearing burns (PeerPool.succeeded).
	// Set HERE, not at the call sites, so the flag and the existence of a prober are one decision.
	pp.proberOwned()
	var busy atomic.Bool
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-t.C:
			due := pp.dueRetests()
			if len(due) == 0 || !busy.CompareAndSwap(false, true) {
				continue
			}
			go func(due []string) {
				defer busy.Store(false)
				for _, addr := range due {
					select {
					case <-closeCh:
						return
					default:
					}
					if pp.retestResult(addr, probe(addr)) {
						ev("heal", "peer-retest", addr)
					}
				}
			}(due)
		}
	}
}
