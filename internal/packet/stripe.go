package packet

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	recHdr      = 12
	maxRecord   = 1 << 20
	stripeIdle  = 20 * time.Second
	stripeRetry = 2 * time.Second

	stripeQueue      = 64
	stripeWriteBytes = 256 << 10
)

func maxStripePend(streams int) int { return streams * (16 << 20) }

var stripeKeepalive = make([]byte, recHdr)

var carrierStreams = 1

func SetHTTPStreams(workers int) {
	if workers > 0 {
		carrierStreams = tclamp(workers, 1, 16)
	}
}

var chunkClasses = func() []int {
	c := []int{4 << 10}
	for base := 4 << 10; base < maxRecord; base <<= 1 {
		for _, q := range []int{5, 6, 7, 8} {
			c = append(c, base*q/4)
		}
	}
	return append(c, maxRecord+recHdr)
}()

var chunkPools = make([]sync.Pool, len(chunkClasses))

func getChunk(n int) *[]byte {
	i := sort.SearchInts(chunkClasses, n)
	if i == len(chunkClasses) {
		b := make([]byte, n)
		return &b
	}
	if p, _ := chunkPools[i].Get().(*[]byte); p != nil {
		*p = (*p)[:n]
		return p
	}
	b := make([]byte, n, chunkClasses[i])
	return &b
}

func putChunk(p *[]byte) {
	if p == nil {
		return
	}
	c := cap(*p)
	if i := sort.SearchInts(chunkClasses, c); i < len(chunkClasses) && chunkClasses[i] == c {
		chunkPools[i].Put(p)
	}
}

type asyncWriter interface {
	write(p []byte, deadline int64) (int, error)
}

type stripeTx struct {
	work chan *[]byte
	done <-chan struct{}
	mu   sync.Mutex
	seq  uint64
}

func newStripeTx(done <-chan struct{}) *stripeTx {
	return &stripeTx{work: make(chan *[]byte, stripeQueue), done: done}
}

func (d *stripeTx) write(p []byte, deadline int64) (int, error) {
	own := getChunk(recHdr + len(p))
	rec := *own
	binary.BigEndian.PutUint32(rec[8:12], uint32(len(p)))
	copy(rec[recHdr:], p)

	d.mu.Lock()
	binary.BigEndian.PutUint64(rec[0:8], d.seq)
	err := d.offer(own, deadline)
	if err == nil {
		d.seq++
	}
	d.mu.Unlock()
	if err != nil {
		putChunk(own)
		return 0, err
	}
	return len(p), nil
}

func (d *stripeTx) offer(rec *[]byte, deadline int64) error {
	select {
	case <-d.done:
		return io.ErrClosedPipe
	default:
	}
	select {
	case d.work <- rec:
		return nil
	default:
	}
	if deadline == 0 {
		select {
		case d.work <- rec:
			return nil
		case <-d.done:
			return io.ErrClosedPipe
		}
	}
	t := time.NewTimer(time.Until(time.Unix(0, deadline)))
	defer t.Stop()
	select {
	case d.work <- rec:
		return nil
	case <-d.done:
		return io.ErrClosedPipe
	case <-t.C:
		return os.ErrDeadlineExceeded
	}
}

func (d *stripeTx) serve(ctx context.Context, w io.Writer, flush func(), setWD func(time.Time) error) {
	buf := make([]byte, 0, stripeWriteBytes+maxRecord)
	tk := time.NewTicker(stripeIdle)
	defer tk.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.done:
			return
		case rec := <-d.work:
			run, single := d.gather(buf, rec)
			if !writeRecord(w, flush, setWD, run) {
				d.requeue(run)
				return
			}
			if single {
				putChunk(rec)
			}
			last = time.Now()
		case now := <-tk.C:
			if now.Sub(last) < stripeIdle {
				continue
			}
			if !writeRecord(w, flush, setWD, stripeKeepalive) {
				return
			}
			last = now
		}
	}
}

func (d *stripeTx) gather(buf []byte, first *[]byte) ([]byte, bool) {
	select {
	case more := <-d.work:
		out := append(append(buf[:0], *first...), *more...)
		putChunk(first)
		putChunk(more)
		for len(out) < stripeWriteBytes {
			select {
			case more := <-d.work:
				out = append(out, *more...)
				putChunk(more)
			default:
				return out, false
			}
		}
		return out, false
	default:
		return *first, true
	}
}

func (d *stripeTx) requeue(run []byte) {
	rec := getChunk(len(run))
	copy(*rec, run)
	select {
	case d.work <- rec:
	case <-d.done:
		putChunk(rec)
	}
}

func writeRecord(w io.Writer, flush func(), setWD func(time.Time) error, rec []byte) bool {
	if setWD != nil {
		_ = setWD(time.Now().Add(writeTimeout))
	}
	if _, err := w.Write(rec); err != nil {
		return false
	}
	flush()
	return true
}

func readStripe(body io.ReadCloser, q *reseq, fail func()) {
	defer body.Close()
	var hdr [recHdr]byte
	for {
		if _, err := io.ReadFull(body, hdr[:]); err != nil {
			return
		}
		seq := binary.BigEndian.Uint64(hdr[0:8])
		n := binary.BigEndian.Uint32(hdr[8:12])
		if n == 0 {
			continue
		}
		if n > maxRecord {
			fail()
			return
		}
		own := getChunk(int(n))
		if _, err := io.ReadFull(body, *own); err != nil {
			putChunk(own)
			return
		}
		if !q.deliver(seq, *own, own) {
			fail()
			return
		}
	}
}

type reseq struct {
	pw      *io.PipeWriter
	floor   int
	max     int
	maxN    int
	streams int
	mu      sync.Mutex
	next    uint64
	pend    map[uint64][]byte
	n       int
}

func newReseq(pw *io.PipeWriter, max int) *reseq {
	q := &reseq{pw: pw, floor: max, pend: map[uint64][]byte{}}
	q.setMax(max)
	return q
}

const perStreamPend = 4 << 20

func (q *reseq) attach(n int) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.streams += n
	m := q.floor + q.streams*perStreamPend
	if lim := maxStripePend(16); m > lim {
		m = lim
	}
	q.setMax(m)
	return q.streams
}

func (q *reseq) setMax(max int) {
	q.max = max
	if q.maxN = max / (8 << 10); q.maxN < 1024 {
		q.maxN = 1024
	}
}

func (q *reseq) deliver(seq uint64, data []byte, own *[]byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if seq < q.next {
		putChunk(own)
		return true
	}
	if len(q.pend) >= q.maxN || q.n+len(data) > q.max {
		putChunk(own)
		return false
	}
	if seq > q.next && own != nil {
		data = append(make([]byte, 0, len(data)), data...)
		putChunk(own)
		own = nil
	}
	if old, ok := q.pend[seq]; ok {
		q.n -= len(old)
	}
	q.pend[seq] = data
	q.n += len(data)
	for {
		d, ok := q.pend[q.next]
		if !ok {
			return true
		}
		delete(q.pend, q.next)
		q.n -= len(d)
		q.next++
		var err error
		if len(d) > 0 {
			_, err = q.pw.Write(d)
		}
		putChunk(own)
		own = nil
		if err != nil {
			return false
		}
	}
}
