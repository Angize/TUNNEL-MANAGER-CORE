package packet

import (
	"sync"
	"time"
)

const portTries = 2

const judgeSilence = 20 * time.Second

type portRung struct {
	mu sync.Mutex

	roll   func(step bool) bool
	settle func()
	spent  int

	dead   func(time.Time) bool
	ready  func() bool
	every  time.Duration
	next   time.Time
	judged time.Time
}

func (p *portRung) setRoll(roll func(step bool) bool) {
	p.mu.Lock()
	p.roll = roll
	p.mu.Unlock()
}

func (p *portRung) setSettle(settle func()) {
	p.mu.Lock()
	p.settle = settle
	p.mu.Unlock()
}

func (p *portRung) setRefresh(dead func(time.Time) bool, ready func() bool, every time.Duration) {
	p.mu.Lock()
	p.dead, p.ready, p.every = dead, ready, every
	p.mu.Unlock()
}

func (p *portRung) tick(now time.Time, judged bool) {
	p.mu.Lock()
	if judged {
		p.judged = now
	}
	roll, settle, dead, ready, every := p.roll, p.settle, p.dead, p.ready, p.every
	quiet := p.judged.IsZero() || now.Sub(p.judged) > judgeSilence
	if p.next.IsZero() && every > 0 {
		p.next = now.Add(jitterFrac(every))
	}
	due := every > 0 && now.After(p.next)
	p.mu.Unlock()

	if settle != nil {
		settle()
	}
	if roll == nil {
		return
	}

	reactive := quiet && dead != nil && dead(now)
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
