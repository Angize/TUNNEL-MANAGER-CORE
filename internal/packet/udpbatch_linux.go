//go:build linux

package packet

import (
	"net"

	"golang.org/x/net/ipv4"
)

type udpBatch struct {
	pc *ipv4.PacketConn
	rb *recvBatcher
	ds []datagram
}

func newUDPBatch(c *net.UDPConn) *udpBatch {
	if c == nil {
		return nil
	}
	return &udpBatch{
		pc: ipv4.NewPacketConn(c),
		rb: newRecvBatcher(maxRecvBatch),
		ds: make([]datagram, 0, maxRecvBatch),
	}
}

func (b *udpBatch) recv() ([]datagram, error) {
	ms, err := b.rb.recv(b.pc)
	if err != nil {
		return nil, err
	}
	b.ds = b.ds[:0]
	for i := range ms {
		ua, ok := ms[i].Addr.(*net.UDPAddr)
		if !ok || ua == nil {
			continue
		}
		b.ds = append(b.ds, datagram{pkt: ms[i].Buffers[0][:ms[i].N], addr: ua})
	}
	return b.ds, nil
}

const (
	gsoMaxSegs  = 45
	gsoMaxBytes = 60000
)

type udpTx struct {
	pc *ipv4.PacketConn
	ms []ipv4.Message
	n  int

	gm    ipv4.Message
	noGSO bool
}

func newUDPTx(c *net.UDPConn) *udpTx {
	if c == nil {
		return nil
	}
	t := &udpTx{pc: ipv4.NewPacketConn(c), ms: make([]ipv4.Message, maxBatch)}
	for i := range t.ms {
		t.ms[i].Buffers = make([][]byte, 1)
	}
	t.gm.Buffers = make([][]byte, 0, gsoMaxSegs)
	return t
}

func (t *udpTx) gsoRun() (segs, size int) {
	if t.n < 2 {
		return 0, 0
	}
	size = len(t.ms[0].Buffers[0])
	if size == 0 {
		return 0, 0
	}
	total := 0
	for i := 0; i < t.n && i < gsoMaxSegs; i++ {
		l := len(t.ms[i].Buffers[0])
		if total+l > gsoMaxBytes {
			break
		}
		if l == size {
			total += l
			segs = i + 1
			continue
		}
		if l < size {
			total += l
			segs = i + 1
		}
		break
	}
	if segs < 2 {
		return 0, 0
	}
	return segs, size
}

func (t *udpTx) sendGSO(segs, size int) int {
	t.gm.Buffers = t.gm.Buffers[:0]
	for i := 0; i < segs; i++ {
		t.gm.Buffers = append(t.gm.Buffers, t.ms[i].Buffers[0])
	}
	t.gm.Addr, t.gm.OOB = t.ms[0].Addr, udpSegmentOOB(size)
	if n, err := t.pc.WriteBatch([]ipv4.Message{t.gm}, 0); err != nil || n < 1 {
		return -1
	}
	return segs
}

func (t *udpTx) reset()     { t.n = 0 }
func (t *udpTx) full() bool { return t.n >= maxBatch }
func (t *udpTx) count() int { return t.n }

func (t *udpTx) add(pkt []byte, to *net.UDPAddr) {
	t.ms[t.n].Buffers[0], t.ms[t.n].Addr = pkt, to
	t.n++
}

func (t *udpTx) flush(errs *sendErrLog) int {
	sent := 0
	if !t.noGSO {
		if segs, size := t.gsoRun(); segs > 0 {
			if n := t.sendGSO(segs, size); n >= 0 {
				sent = n
			} else {
				t.noGSO = true
			}
		}
	}
	if sent < t.n {
		if n := sendBatch(t.pc, t.ms[sent:t.n]); n != t.n-sent {
			errs.note("udp/batch", errShortBatch)
			sent += n
		} else {
			sent = t.n
		}
	}
	return sent
}
