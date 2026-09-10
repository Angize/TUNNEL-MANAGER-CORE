package packet

import (
	"log"
	"sync"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const rxQueueDepth = 256

type tunWriters struct {
	devs []*tun.Device
	ch   []chan []byte
	done chan struct{}
	once sync.Once
}

func newTunWriters(devs []*tun.Device) *tunWriters {
	w := &tunWriters{devs: devs, done: make(chan struct{}), ch: make([]chan []byte, len(devs))}
	for i := range devs {
		w.ch[i] = make(chan []byte, rxQueueDepth)
		go w.run(i)
	}
	return w
}

func (w *tunWriters) run(i int) {
	pend := make([][]byte, 0, rxQueueDepth)
	for {
		select {
		case pkt := <-w.ch[i]:
			pend = w.drain(i, append(pend[:0], pkt))
			w.put(i, pend)
			clear(pend)
		case <-w.done:
			return
		}
	}
}

func (w *tunWriters) drain(i int, pend [][]byte) [][]byte {
	for len(pend) < cap(pend) {
		select {
		case p := <-w.ch[i]:
			pend = append(pend, p)
		default:
			return pend
		}
	}
	return pend
}

func (w *tunWriters) put(i int, pkts [][]byte) {
	if err := w.devs[i].WriteBatch(pkts); err != nil {
		log.Printf("core: tun write error: %v", err)
	}
}

func (w *tunWriters) write(pkt []byte) {
	i := 0
	if n := len(w.ch); n > 1 {
		i = int(flowHash(pkt) % uint32(n))
	}
	select {
	case w.ch[i] <- pkt:
	case <-w.done:
	}
}

func (w *tunWriters) close() { w.once.Do(func() { close(w.done) }) }

func flowHash(p []byte) uint32 {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0
	}
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for _, c := range p[12:20] {
		h = (h ^ uint32(c)) * prime
	}
	if ihl := int(p[0]&0x0f) * 4; ihl >= 20 && len(p) >= ihl+4 {
		switch p[9] {
		case 6, 17:
			for _, c := range p[ihl : ihl+4] {
				h = (h ^ uint32(c)) * prime
			}
		}
	}
	return h
}
