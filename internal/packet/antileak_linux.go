//go:build linux

package packet

import (
	"net"
	"sync"
	"sync/atomic"
)

// antiLeaker owns the firewall rules a carrier installs so the peer's — or our own — kernel does not
// answer its carrier packets. flux taps at AF_PACKET before netfilter and drops the inbound frame; raw
// reads a socket delivered after PREROUTING and INPUT, so it must suppress the kernel's ANSWER on the way
// out instead. Rules are scoped to ONE peer and re-scoped on rotation; every entry point is idempotent.
type antiLeaker struct {
	install func(peer net.IP) func() // installs this carrier's rules for peer, returns their removal (nil if none went in)
	closeCh <-chan struct{}          // the carrier's close channel: never install a rule teardown will not remove

	cur   atomic.Pointer[func()] // removal for the rules CURRENTLY installed; swapped on each re-scope, read by teardown
	mu    sync.Mutex             // serializes re-scoping (rotate / pin / learnPeer) against teardown
	curIP net.IP                 // the IP the installed rules are scoped to (guarded by mu); nil = none installed
	want  atomic.Pointer[net.IP] // the IP they SHOULD be scoped to; apply re-reads it under mu
}

// init wires the installer and the carrier's close channel. Call once, from the constructor,
// before Run. Leaving it uncalled is what keeps a hand-built carrier off the host firewall.
func (a *antiLeaker) init(closeCh <-chan struct{}, install func(peer net.IP) func()) {
	a.closeCh = closeCh
	a.install = install
}

// scope re-scopes the rules to peer on the CALLER's goroutine. For callers that are not on the
// data path: a dial, a rotation timer, the pin poller.
func (a *antiLeaker) scope(peer net.IP) {
	if a.wants(peer) {
		a.apply()
	}
}

// scopeAsync is scope with an OFF-GOROUTINE apply, for callers on the data path. learnPeer runs on the
// single receive goroutine and a re-scope forks a process per rule twice over, so doing it inline stalls
// the receive loop for as long as iptables takes — a visible pause in the download on every rotation.
// Ordering is safe without a queue: apply re-reads the DESIRED peer under mu, so both hands converge.
func (a *antiLeaker) scopeAsync(peer net.IP) {
	if a.wants(peer) {
		go a.apply()
	}
}

// wants records the peer the rules SHOULD be scoped to and reports whether that is a change.
// Steady state — every authenticated frame calls through here — is one atomic load and no lock.
func (a *antiLeaker) wants(peer net.IP) bool {
	v4 := peer.To4()
	if v4 == nil {
		return false
	}
	if cur := a.want.Load(); cur != nil && cur.Equal(v4) {
		return false
	}
	cp := append(net.IP(nil), v4...)
	a.want.Store(&cp)
	return true
}

// apply brings the installed rules in line with want. Idempotent.
func (a *antiLeaker) apply() {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.closeCh:
		return // shutting down: don't install a rule teardown won't remove
	default:
	}
	if a.install == nil {
		return // no installer wired (a hand-built carrier in a test) — never touch the host firewall
	}
	want := a.want.Load()
	if want == nil {
		return
	}
	v4 := *want
	if a.curIP != nil && a.curIP.Equal(v4) {
		return // already scoped to this peer — no iptables churn on every frame
	}
	// Install the NEW scope BEFORE removing the old one. Removing first left a window with no rule at
	// all, and a destination rotation lands squarely in it: SetPeerPool deliberately keeps admitting
	// the endpoint we just left for the frames still in flight from it, and in that gap the kernel
	// answered each of them — the exact leak these rules exist to stop.
	fn := a.install(v4)
	old := a.cur.Swap(&fn)
	a.curIP = append(net.IP(nil), v4...)
	if old != nil && *old != nil {
		(*old)()
	}
}

// teardown removes whatever is installed. The caller closes closeCh FIRST, so any re-scope that
// now acquires mu bails out; taking mu here orders us after an in-flight apply so we remove the
// rules it left behind rather than racing it.
func (a *antiLeaker) teardown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p := a.cur.Load(); p != nil && *p != nil {
		(*p)()
	}
	a.cur.Store(nil)
	a.curIP = nil
}
