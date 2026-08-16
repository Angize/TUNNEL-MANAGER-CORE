// One TUN writer per queue, so received packets stop queueing behind a single file descriptor.
//
// Carrier-agnostic on purpose: the packet handed in is already plaintext, so nothing here knows which
// carrier decrypted it. Portable for the same reason -- it uses only the device's Write, which exists
// off linux too, and a carrier that lives in a portable file could not reference it otherwise.
//
// A cpu profile of a saturated RECEIVING end, taken on a production node, put 71% of the process in
// syscalls and 3.1% in the AEAD. The cost is the write, not the crypto -- so the crypto stays where it
// is, on the single reader, and the writes are what gets spread.
//
// Ordering is kept BY CONSTRUCTION rather than by a resequencer, which is what makes this safe: one
// reader decrypts and dispatches in arrival order, and a packet's writer is picked from the packet's
// own addresses and ports. Every packet of a connection therefore lands on the same writer and reaches
// the TUN in the order it arrived. Different connections may interleave differently, which is what the
// network does to them anyway.
package packet

import (
	"log"
	"sync"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// rxQueueDepth bounds how far one writer may fall behind before its packets are dropped instead of the
// reader being blocked. A datagram carrier drops and the tunnelled L4 retransmits; a reader parked on
// one slow writer would stall every OTHER connection along with it.
const rxQueueDepth = 256

// tunWriters spreads TUN writes across a device's queues.
type tunWriters struct {
	devs []*tun.Device
	ch   []chan []byte // nil for a single-queue carrier; ch[0] is always nil (written inline)
	done chan struct{}
	once sync.Once
}

// newTunWriters starts one goroutine per EXTRA queue. Queue 0 is written inline by the reader, so a
// single-queue carrier keeps exactly the path it had: no channel, no goroutine, no added latency.
func newTunWriters(devs []*tun.Device) *tunWriters {
	w := &tunWriters{devs: devs, done: make(chan struct{})}
	if len(devs) < 2 {
		return w
	}
	w.ch = make([]chan []byte, len(devs))
	for i := 1; i < len(devs); i++ {
		w.ch[i] = make(chan []byte, rxQueueDepth)
		go w.run(i)
	}
	return w
}

func (w *tunWriters) run(i int) {
	for {
		select {
		case pkt := <-w.ch[i]:
			w.put(i, pkt)
		case <-w.done:
			return
		}
	}
}

func (w *tunWriters) put(i int, pkt []byte) {
	if _, err := w.devs[i].Write(pkt); err != nil {
		log.Printf("core: tun write error: %v", err)
	}
}

// write hands one L3 packet to the writer that owns its flow.
//
// pkt must not be touched afterwards: it is handed to another goroutine. Every caller passes a buffer
// the AEAD allocated for this frame alone, so there is nothing to copy.
func (w *tunWriters) write(pkt []byte) {
	i := 0
	if n := len(w.ch); n > 1 {
		i = int(flowHash(pkt) % uint32(n))
	}
	if i == 0 {
		w.put(0, pkt)
		return
	}
	select {
	case w.ch[i] <- pkt:
	default: // that writer is behind; drop, exactly as this carrier drops everywhere else
	}
}

// spread reports whether writes actually go to more than one queue. Callers use it to decide whether a
// packet is about to cross a goroutine boundary, which is the only case where a buffer they do not own
// has to be copied.
func (w *tunWriters) spread() bool { return len(w.ch) > 1 }

func (w *tunWriters) close() { w.once.Do(func() { close(w.done) }) }

// flowHash keys a packet to a writer by its own addresses and ports, so one connection never straddles
// two writers and cannot be reordered against itself.
//
// Anything it cannot parse hashes to 0, the reader's own queue: correct, simply not spread. That
// covers non-IPv4, runts, and protocols with no ports -- none of which carry the bulk traffic this
// exists for.
func flowHash(p []byte) uint32 {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0
	}
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for _, c := range p[12:20] { // source and destination address
		h = (h ^ uint32(c)) * prime
	}
	if ihl := int(p[0]&0x0f) * 4; ihl >= 20 && len(p) >= ihl+4 {
		switch p[9] { // protocol
		case 6, 17: // tcp, udp: both ports sit in the first four bytes of the payload
			for _, c := range p[ihl : ihl+4] {
				h = (h ^ uint32(c)) * prime
			}
		}
	}
	return h
}
