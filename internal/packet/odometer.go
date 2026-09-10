package packet

import "sync"

type odometer struct {
	mu   sync.Mutex
	rot  int
	want int
	tick int
}

func (o *odometer) failed(eligible func() int) (advanceHigh bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rot == 0 {
		o.want = eligible()
	}
	if o.rot++; o.rot >= o.want {
		o.rot = 0
		return true
	}
	return false
}

func (o *odometer) beat(moved bool, eligible func() int) (advanceHigh bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tick++
	if !moved || o.tick >= eligible() {
		o.tick, o.rot, o.want = 0, 0, 0
		return true
	}
	return false
}

func (o *odometer) restart() {
	o.mu.Lock()
	o.rot, o.want = 0, 0
	o.mu.Unlock()
}
