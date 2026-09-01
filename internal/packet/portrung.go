package packet

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
)

var portTries = 2

const (
	repairPortLo = 32768
	repairPortHi = 46999
)

func rollRepairPort() uint16 {
	n := repairPortHi - repairPortLo + 1
	limit := 65536 - (65536 % n)
	for i := 0; i < 8; i++ {
		var rb [2]byte
		if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
			return 0
		}
		if v := int(binary.BigEndian.Uint16(rb[:])); v < limit {
			return uint16(repairPortLo + v%n)
		}
	}
	return 0
}

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
