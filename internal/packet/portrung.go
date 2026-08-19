package packet

import "sync"

const portTries = 2

type portRung struct {
	mu sync.Mutex

	roll  func() bool
	spent int
}

func (p *portRung) setRoll(roll func() bool) {
	p.mu.Lock()
	p.roll = roll
	p.mu.Unlock()
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
