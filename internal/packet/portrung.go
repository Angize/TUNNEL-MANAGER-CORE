package packet

import (
	"sync"
)

var portTries = 2

const MaxPortTries = 60

func SetPortTries(n int) {
	if n > 0 {
		portTries = n
	}
}

type rung struct {
	mu sync.Mutex

	act   func() bool
	spent int
}

func (p *rung) set(act func() bool) {
	p.mu.Lock()
	p.act = act
	p.mu.Unlock()
}

func (p *rung) armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.act != nil
}

func (p *rung) try(budget int) bool {
	p.mu.Lock()
	act := p.act
	if act == nil || p.spent >= budget {
		p.mu.Unlock()
		return false
	}
	p.spent++
	p.mu.Unlock()

	if act() {
		return true
	}
	p.mu.Lock()
	p.spent--
	p.mu.Unlock()
	return false
}

func (p *rung) restart() {
	p.mu.Lock()
	p.spent = 0
	p.mu.Unlock()
}
