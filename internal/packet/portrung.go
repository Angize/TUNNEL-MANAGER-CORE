package packet

import (
	"sync"
	"time"
)

const portTries = 2

const judgeSilence = 20 * time.Second

type portRung struct {
	mu sync.Mutex

	roll   func() bool
	dead   func(time.Time) bool
	spent  int
	judged time.Time
}

func (p *portRung) setRoll(roll func() bool, dead func(time.Time) bool) {
	p.mu.Lock()
	p.roll, p.dead = roll, dead
	p.mu.Unlock()
}

func (p *portRung) tick(now time.Time, judged bool) {
	p.mu.Lock()
	if judged {
		p.judged = now
	}
	roll, dead := p.roll, p.dead
	quiet := p.judged.IsZero() || now.Sub(p.judged) > judgeSilence
	p.mu.Unlock()

	if roll == nil || dead == nil || !quiet || !dead(now) {
		return
	}
	roll()
}

func (p *portRung) armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.roll != nil
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

	if roll() {
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
