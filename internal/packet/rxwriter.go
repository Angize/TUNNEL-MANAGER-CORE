package packet

import (
	"log"
	"sync"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

const (
	rxQueueDepth = 256
	rxBufLen     = 2048
)

var rxBufs = sync.Pool{New: func() any {
	b := make([]byte, rxBufLen)
	return &b
}}

func getRxBuf() *[]byte { return rxBufs.Get().(*[]byte) }

func putRxBuf(b *[]byte) {
	if b != nil {
		rxBufs.Put(b)
	}
}

type rxPkt struct {
	b   []byte
	own *[]byte
}

type tunWriters struct {
	devs []*tun.Device
	ch   []chan rxPkt
	done chan struct{}
	once sync.Once
}

func newTunWriters(devs []*tun.Device) *tunWriters {
	w := &tunWriters{devs: devs, done: make(chan struct{}), ch: make([]chan rxPkt, len(devs))}
	for i := range devs {
		w.ch[i] = make(chan rxPkt, rxQueueDepth)
		go w.run(i)
	}
	return w
}

func (w *tunWriters) run(i int) {
	pend := make([]rxPkt, 0, rxQueueDepth)
	pkts := make([][]byte, 0, rxQueueDepth)
	for {
		select {
		case p := <-w.ch[i]:
			pend = w.drain(i, append(pend[:0], p))
			pkts = pkts[:0]
			for _, q := range pend {
				pkts = append(pkts, q.b)
			}
			w.put(i, pkts)
			for _, q := range pend {
				putRxBuf(q.own)
			}
			clear(pend)
			clear(pkts)
		case <-w.done:
			return
		}
	}
}

func (w *tunWriters) drain(i int, pend []rxPkt) []rxPkt {
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

func (w *tunWriters) writeOwned(pkt []byte, own *[]byte) {
	i := 0
	if n := len(w.ch); n > 1 {
		i = int(flowHash(pkt) % uint32(n))
	}
	select {
	case w.ch[i] <- rxPkt{b: pkt, own: own}:
	case <-w.done:
		putRxBuf(own)
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
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}
