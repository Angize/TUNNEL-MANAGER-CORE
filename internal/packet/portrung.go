package packet

import "sync"

// How many source ports this tunnel's ladder may draw before it moves on. Each draw costs one probe
// verdict, and a tunnel with a single destination and a single source has nothing after them.
var portTries = 2

// SetPortTries takes the operator's number for THIS tunnel. 0 keeps the default; the range matches the
// panel's.
func SetPortTries(n int) {
	if n <= 0 {
		return
	}
	if n > 50 {
		n = 50
	}
	portTries = n
}

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
