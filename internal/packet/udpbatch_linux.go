//go:build linux

package packet

import (
	"net"

	"golang.org/x/net/ipv4"
)

// udpBatch reads a burst off one udp socket in a single recvmmsg. It owns the buffers, so the caller
// must finish with one batch before asking for the next.
type udpBatch struct {
	pc *ipv4.PacketConn
	rb *recvBatcher
	ds []datagram
}

// newUDPBatch wraps a socket. A nil socket gives a nil batcher rather than an error: batching is an
// optimisation, and the caller's single-datagram read is always there.
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

// recv blocks for the first datagram and takes whatever else is already queued behind it.
//
// A message whose address is not a udp one is dropped rather than passed on with a nil address: every
// receive path here keys the peer, the replay window and the reply socket off that address.
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

// gsoMaxSegs and gsoMaxBytes bound one segmentation-offload write. The kernel caps a datagram at 64 KiB
// however it is segmented, and refuses more than 64 segments; both are held under with room to spare,
// because exceeding either fails the whole write rather than trimming it.
const (
	gsoMaxSegs  = 45
	gsoMaxBytes = 60000
)

// udpTx sends a burst of frames in one syscall.
//
// Two shapes. Frames of EQUAL size go as a single datagram carrying a UDP_SEGMENT control message: the
// kernel walks the stack once and cuts the buffer into segments at the end, which is the same trick TSO
// plays for tcp and the reason a tcp flow reaches several times a udp flow's packet rate on one queue.
// Anything else falls back to sendmmsg -- still one syscall, but N trips through the stack.
//
// The wire is identical either way: the peer receives the same datagrams with the same headers.
//
// The message array AND its one-element Buffers slices are built once and then only re-pointed at each
// frame. Writing `ipv4.Message{Buffers: [][]byte{pkt}}` per packet allocates that inner slice on the
// hottest path there is.
type udpTx struct {
	pc *ipv4.PacketConn
	ms []ipv4.Message
	n  int
	// gm is the segmentation-offload message: its Buffers are the frames themselves, gathered by the
	// kernel, so the run needs no copy. noGSO latches when the kernel refuses one, so a host without it
	// pays the failure once instead of once per burst.
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

// gsoRun reports how many leading frames may go as one segmented datagram, and the segment size.
//
// Every segment but the LAST must be the same length -- that is the kernel's rule, and it is what makes
// a bulk transfer's stream of full-MTU frames the case this exists for. A run of one is not worth a
// control message, so it reports 0.
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
		if l < size { // a shorter final segment is allowed, and only as the last one
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

// sendGSO writes segs frames as one segmented datagram. It reports how many frames left, or -1 when the
// kernel would not take it at all, which tells the caller to fall back for this burst.
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

// add holds one frame for the next flush. pkt must be storage the caller does not reuse before then --
// every framing path here seals into a fresh buffer, so it is.
func (t *udpTx) add(pkt []byte, to *net.UDPAddr) {
	t.ms[t.n].Buffers[0], t.ms[t.n].Addr = pkt, to
	t.n++
}

// flush sends what was added and reports how many left.
//
// A short write is not an error to retry: sendmmsg says how many messages it accepted and the rest are
// dropped here, which is the contract the single-packet path already has with the kernel. Re-sending
// the accepted ones would duplicate packets that already went.
func (t *udpTx) flush(errs *sendErrLog) int {
	sent := 0
	if !t.noGSO {
		if segs, size := t.gsoRun(); segs > 0 {
			if n := t.sendGSO(segs, size); n >= 0 {
				sent = n
			} else {
				// Latched, not retried: a kernel or socket that will not segment says so every time, and
				// the whole burst still goes below through sendmmsg.
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
