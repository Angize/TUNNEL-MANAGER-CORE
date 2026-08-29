//go:build linux

package packet

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	antiLeakRetryMin = 2 * time.Second
	antiLeakRetryMax = time.Minute

	antiLeakLinger = 5 * time.Second
)

const antiLeakMaxLinger = 4

type antiLeaker struct {
	install func(peer net.IP) (remove func(), ok bool)
	closeCh <-chan struct{}

	cur   atomic.Pointer[func()]
	mu    sync.Mutex
	curIP net.IP
	want  atomic.Pointer[net.IP]
	retry *time.Timer
	wait  time.Duration

	pending []*lingering
}

type lingering struct {
	ip     net.IP
	remove func()
	timer  *time.Timer
}

func (a *antiLeaker) init(closeCh <-chan struct{}, install func(peer net.IP) (func(), bool)) {
	a.closeCh = closeCh
	a.install = install
}

func (a *antiLeaker) scope(peer net.IP) {
	if a.wants(peer) {
		a.apply()
	}
}

func (a *antiLeaker) scopeAsync(peer net.IP) {
	if a.wants(peer) {
		go a.apply()
	}
}

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

func (a *antiLeaker) apply() {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.closeCh:
		return
	default:
	}
	if a.install == nil {
		return
	}
	want := a.want.Load()
	if want == nil {
		return
	}
	v4 := *want
	if a.curIP != nil && a.curIP.Equal(v4) {
		return
	}

	fn, ok := a.takeLingeringLocked(v4)
	if fn == nil && !ok {
		fn, ok = a.install(v4)
	}
	if !ok {
		if fn != nil {
			fn()
		}
		a.armRetryLocked(v4)
		return
	}
	a.wait = 0
	old := a.cur.Swap(&fn)
	oldIP := a.curIP
	a.curIP = append(net.IP(nil), v4...)
	if old != nil && *old != nil {
		a.lingerLocked(oldIP, *old)
	}
}

func (a *antiLeaker) lingerLocked(ip net.IP, remove func()) {
	if ip == nil {
		remove()
		return
	}
	for len(a.pending) >= antiLeakMaxLinger {
		a.dropLingeringLocked(0)
	}
	l := &lingering{ip: append(net.IP(nil), ip...), remove: remove}
	l.timer = time.AfterFunc(antiLeakLinger, func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		for i, p := range a.pending {
			if p == l {
				a.dropLingeringLocked(i)
				return
			}
		}
	})
	a.pending = append(a.pending, l)
}

func (a *antiLeaker) takeLingeringLocked(ip net.IP) (func(), bool) {
	for i, p := range a.pending {
		if p.ip.Equal(ip) {
			p.timer.Stop()
			a.pending = append(a.pending[:i:i], a.pending[i+1:]...)
			return p.remove, true
		}
	}
	return nil, false
}

func (a *antiLeaker) dropLingeringLocked(i int) {
	p := a.pending[i]
	p.timer.Stop()
	a.pending = append(a.pending[:i:i], a.pending[i+1:]...)
	p.remove()
}

func (a *antiLeaker) armRetryLocked(peer net.IP) {
	if a.retry != nil {
		return
	}
	select {
	case <-a.closeCh:
		return
	default:
	}
	switch {
	case a.wait == 0:
		a.wait = antiLeakRetryMin
	case a.wait < antiLeakRetryMax:
		a.wait *= 2
	}
	if a.wait > antiLeakRetryMax {
		a.wait = antiLeakRetryMax
	}
	log.Printf("anti-leak: the firewall rules for %s did not go in — retrying in %s; until they do, the kernel answers this peer's carrier packets", peer, a.wait)
	a.retry = time.AfterFunc(a.wait, func() {
		a.mu.Lock()
		a.retry = nil
		a.mu.Unlock()
		a.apply()
	})
}

func (a *antiLeaker) teardown() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.retry != nil {
		a.retry.Stop()
		a.retry = nil
	}
	for len(a.pending) > 0 {
		a.dropLingeringLocked(0)
	}
	if p := a.cur.Load(); p != nil && *p != nil {
		(*p)()
	}
	a.cur.Store(nil)
	a.curIP = nil
}
