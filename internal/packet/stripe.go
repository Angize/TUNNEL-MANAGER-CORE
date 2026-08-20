package packet

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"time"
)

// A download stream carries records: an 8-byte sequence number, a 4-byte length, then that many bytes.
// A zero length is a keepalive — it holds an otherwise idle response open without taking a position in
// the sequence.
const (
	recHdr      = 12
	maxRecord   = 1 << 20
	stripeIdle  = 20 * time.Second
	stripeRetry = 2 * time.Second

	// What one stream will gather into a single write. The handoff returns before the network write,
	// so the producer no longer waits for the wire and hands over half-full batches; gathering them
	// back is what keeps a write the size it was when the producer blocked on it.
	stripeQueue      = 64
	stripeWriteBytes = 256 << 10
)

// The gap the receiver will hold. A write returns once the kernel has the bytes, not once the far end
// does, so a stream that falls behind keeps taking records into its own send buffer: the gap a set of
// streams can open is about one bandwidth-delay product each. Measured on a 72 ms path at ~1 Gbit it
// reaches 25 MB across four streams and 34 across eight.
func maxStripePend(streams int) int { return streams * (16 << 20) }

var stripeKeepalive = make([]byte, recHdr)

var carrierStreams = 1

func SetHTTPStreams(workers int) {
	if workers > 0 {
		carrierStreams = tclamp(workers, 1, 16)
	}
}

// What a carrier writes into when the network write must not happen on the caller's goroutine.
type asyncWriter interface {
	write(p []byte, deadline int64) (int, error)
}

// The server end of a parallel download: one queue, and one consumer per attached stream. Whichever
// stream is free takes the next record, so a slow one does not hold the others up.
type stripeTx struct {
	work chan []byte
	done <-chan struct{}
	mu   sync.Mutex
	seq  uint64
}

func newStripeTx(done <-chan struct{}) *stripeTx {
	return &stripeTx{work: make(chan []byte, stripeQueue), done: done}
}

// Numbers the chunk and hands it off. The copy is what buys the parallelism: returning before the
// network write lets the next chunk go to a different stream.
func (d *stripeTx) write(p []byte, deadline int64) (int, error) {
	rec := make([]byte, recHdr+len(p))
	binary.BigEndian.PutUint32(rec[8:12], uint32(len(p)))
	copy(rec[recHdr:], p)

	d.mu.Lock()
	binary.BigEndian.PutUint64(rec[0:8], d.seq)
	d.seq++
	err := d.offer(rec, deadline)
	d.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Held across the handoff so a record cannot reach a stream ahead of a lower-numbered one still
// waiting for room. The receiver holds a bounded gap, and an inversion the size of that buffer would
// end the carrier rather than reorder it.
func (d *stripeTx) offer(rec []byte, deadline int64) error {
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

// One attached stream, until its request is gone, the session ends, or its write fails. A stream is
// disposable: what it failed to write goes back on the queue for whichever stream is still up, so
// losing one costs throughput rather than the carrier. The request context is what releases a stream
// whose client walked away without saying so — an idle one writes nothing, so no write would ever
// fail to notice.
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
			run := d.gather(buf, rec)
			if !writeRecord(w, flush, setWD, run) {
				d.requeue(run)
				return
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

// Takes whatever else is already queued, up to one write's worth, into the stream's own buffer.
// Records are self-delimiting, so a gathered run is one write on the wire and still one record at a
// time to the reader.
func (d *stripeTx) gather(buf, first []byte) []byte {
	select {
	case more := <-d.work:
		out := append(append(buf[:0], first...), more...)
		for len(out) < stripeWriteBytes {
			select {
			case more := <-d.work:
				out = append(out, more...)
			default:
				return out
			}
		}
		return out
	default:
		return first
	}
}

// A run that never reached the wire, put back for another stream. The client resequences, so it does
// not matter which stream carries it or in what order it arrives; what matters is that the numbers in
// it are not simply gone, because the receiver would then wait for them forever.
func (d *stripeTx) requeue(run []byte) {
	rec := make([]byte, len(run))
	copy(rec, run)
	select {
	case d.work <- rec:
	case <-d.done:
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

// Reads records off one download stream into the shared resequencer. Returning means this stream is
// finished — the caller opens another. Only the resequencer ends the carrier, and only when the gap
// it is holding outgrows its buffer.
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
		buf := make([]byte, n)
		if _, err := io.ReadFull(body, buf); err != nil {
			return
		}
		if !q.deliver(seq, buf) {
			fail()
			return
		}
	}
}

// Puts numbered chunks back in order and writes out whatever run has become contiguous. Both
// directions of the http carrier arrive out of order, and both bound the gap they will hold.
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

// The entry cap is derived from the byte cap rather than fixed, because the two directions do not
// carry the same size of record: an upstream chunk is a whole batch, a downstream one is whatever the
// tunnel handed over. A fixed 1024 is a 128 MB gap upstream and a 25 MB one downstream, so downstream
// it — and only it — ended the carrier while the byte cap it was given sat untouched.
func newReseq(pw *io.PipeWriter, max int) *reseq {
	q := &reseq{pw: pw, floor: max, pend: map[uint64][]byte{}}
	q.setMax(max)
	return q
}

// One h2 stream can hold a flow-control window and no more, so the gap a striped sender opens grows
// with the streams it has attached. Counting them is what stops a peer that has authenticated nothing
// from parking the whole budget on a single stream.
const perStreamPend = 4 << 20

// Returns how many streams are attached after the change. A carrier lives while at least one is: at
// zero it has nothing left to carry, and both ends end it rather than hold a session open for an idle
// timeout with nobody on the other side.
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

// False means the gap outgrew the buffer, or the far side is gone: the caller must drop the carrier.
func (q *reseq) deliver(seq uint64, data []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if seq < q.next {
		return true
	}
	if len(q.pend) >= q.maxN || q.n+len(data) > q.max {
		return false
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
		if len(d) > 0 {
			if _, err := q.pw.Write(d); err != nil {
				return false
			}
		}
	}
}
