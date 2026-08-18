package packet

import (
	"sync"
	"time"
)

const portTries = 2

type portRung struct {
	mu sync.Mutex

	roll  func(step bool) bool
	spent int

	dead  func(time.Time) bool
	ready func() bool
	every time.Duration
	next  time.Time
}

func (p *portRung) setRoll(roll func(step bool) bool) {
	p.mu.Lock()
	p.roll = roll
	p.mu.Unlock()
}

func (p *portRung) setRefresh(dead func(time.Time) bool, ready func() bool, every time.Duration) {
	p.mu.Lock()
	p.dead, p.ready, p.every = dead, ready, every
	p.mu.Unlock()
}

func (p *portRung) tick(now time.Time, judged bool) {
	p.mu.Lock()
	roll, dead, ready, every := p.roll, p.dead, p.ready, p.every
	if roll == nil {
		p.mu.Unlock()
		return
	}
	if p.next.IsZero() && every > 0 {
		p.next = now.Add(jitterFrac(every))
	}
	due := every > 0 && now.After(p.next)
	p.mu.Unlock()

	reactive := dead != nil && dead(now)
	if !reactive && (!due || judged || (ready != nil && !ready())) {
		return
	}

	p.mu.Lock()
	if every > 0 {
		p.next = now.Add(jitterFrac(every))
	}
	p.mu.Unlock()
	roll(reactive)
}

func (p *portRung) armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.roll != nil && (p.every > 0 || p.dead != nil)
}

func (p *portRung) try() bool {
	p.mu.Lock()
	roll := p.roll
	if roll == nil || p.spent >= portTries {
		p.mu.Unlock()
		return false
	}
	p.spent++
	p.mu.Unlock()

	if roll(true) {
		return true
	}
	p.mu.Lock()
	p.spent--
	p.mu.Unlock()
	return false
}

func (p *portRung) restart() {
	p.mu.Lock()
	p.spent = 0
	p.mu.Unlock()
}
