package packet

import (
	"encoding/binary"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

func newFecPair(fec bool, data, parity int, name string, emit, deliver func([]byte)) (*fecEncoder, *fecDecoder) {
	if !fec {
		return nil, nil
	}
	enc, err := newFecEncoder(data, parity, emit)
	if err != nil {
		log.Printf("%s: FEC disabled (bad geometry %d+%d): %v", name, data, parity, err)
		return nil, nil
	}
	return enc, newFecDecoder(enc.codec, deliver)
}

func fecTag(enc *fecEncoder, frame []byte) []byte {
	if enc == nil {
		return frame
	}
	return append([]byte{fecTypePass}, frame...)
}

const (
	fecTypePass   = 0
	fecTypeData   = 1
	fecTypeParity = 2
	fecHdrLen     = 1 + 4 + 1 + 1 + 1 + 1 + 2
	fecFlushDelay = 15 * time.Millisecond
	fecKeepBlocks = 64
	fecMaxBytes   = 64 << 20

	fecMaxShardLen = 16 << 10
)

type fecEncoder struct {
	codec *fecCodec
	n, k  int
	emit  func([]byte)

	mu     sync.Mutex
	block  uint32
	shards [][]byte
	timer  *time.Timer
	closed bool
}

func newFecEncoder(n, k int, emit func([]byte)) (*fecEncoder, error) {
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil, err
	}
	return &fecEncoder{codec: c, n: n, k: k, emit: emit}, nil
}

func (e *fecEncoder) Close() {
	e.mu.Lock()
	e.closed = true
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.mu.Unlock()
}

func (e *fecEncoder) addData(sealed []byte) {
	sp := make([]byte, 2+len(sealed))
	binary.BigEndian.PutUint16(sp[:2], uint16(len(sealed)))
	copy(sp[2:], sealed)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.shards = append(e.shards, sp)
	if len(e.shards) >= e.n {
		e.flushLocked()
	} else if e.timer == nil {
		e.timer = time.AfterFunc(fecFlushDelay, func() { e.mu.Lock(); e.flushLocked(); e.mu.Unlock() })
	}
	e.mu.Unlock()
}

func (e *fecEncoder) flushLocked() {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	if e.closed {
		return
	}
	count := len(e.shards)
	if count == 0 {
		return
	}
	shardLen := 0
	for _, s := range e.shards {
		if len(s) > shardLen {
			shardLen = len(s)
		}
	}
	data := make([][]byte, e.n)
	for i := 0; i < e.n; i++ {
		data[i] = make([]byte, shardLen)
		if i < count {
			copy(data[i], e.shards[i])
		}
	}
	parity, err := e.codec.Encode(data)
	blk := e.block
	e.block++
	queued := e.shards
	e.shards = nil
	if err != nil {
		return
	}
	hdr := func(typ byte, idx int) []byte {
		h := make([]byte, fecHdrLen)
		h[0] = typ
		binary.BigEndian.PutUint32(h[1:5], blk)
		h[5] = byte(idx)
		h[6] = byte(e.n)
		h[7] = byte(e.k)
		h[8] = byte(count)
		binary.BigEndian.PutUint16(h[9:11], uint16(shardLen))
		return h
	}

	for i := 0; i < count; i++ {
		e.emit(append(hdr(fecTypeData, i), queued[i]...))
	}

	kEff := (e.k*count + e.n - 1) / e.n
	for i := 0; i < kEff; i++ {
		e.emit(append(hdr(fecTypeParity, i), parity[i]...))
	}
}

type fecBlock struct {
	count, shardLen int
	shards          [][]byte
	present         int
	bytes           int
	arrival         uint64
	done            bool

	gaveOut []bool
}

type fecDecoder struct {
	mu       sync.Mutex
	blocks   map[uint32]*fecBlock
	seq      uint64
	bytes    int
	maxBytes int
	n, k     int
	codec    *fecCodec
	deliver  func([]byte)

	resetPending atomic.Bool
}

func newFecDecoder(c *fecCodec, deliver func([]byte)) *fecDecoder {
	return &fecDecoder{blocks: map[uint32]*fecBlock{}, maxBytes: fecMaxBytes,
		n: c.n, k: c.k, codec: c, deliver: deliver}
}

func (d *fecDecoder) reset() {
	if d == nil {
		return
	}
	d.resetPending.Store(true)
}

func (d *fecDecoder) dropBlocksLocked() {
	d.blocks = map[uint32]*fecBlock{}
	d.bytes = 0
}

func (d *fecDecoder) input(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case fecTypePass:
		if len(pkt) < 2 {
			return
		}
		d.deliver(pkt[1:])
		return
	case fecTypeData, fecTypeParity:
	default:
		return
	}
	if len(pkt) < fecHdrLen {
		return
	}
	typ := pkt[0]
	blk := binary.BigEndian.Uint32(pkt[1:5])
	idx := int(pkt[5])
	n, k, count := int(pkt[6]), int(pkt[7]), int(pkt[8])
	shardLen := int(binary.BigEndian.Uint16(pkt[9:11]))
	shard := pkt[fecHdrLen:]
	if n != d.n || k != d.k || count < 1 || count > n || shardLen < 2 || shardLen > fecMaxShardLen {
		return
	}

	if typ == fecTypeData {
		if len(shard) < 2 || len(shard) > shardLen {
			return
		}
	} else if len(shard) != shardLen {
		return
	}
	slot := idx
	if typ == fecTypeParity {
		slot = n + idx
	}
	if slot < 0 || slot >= n+k {
		return
	}
	if typ == fecTypeData && idx >= count {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.resetPending.Swap(false) {
		d.dropBlocksLocked()
	}
	b := d.blocks[blk]
	if b == nil {
		padBytes := 0
		if count < n {
			padBytes = shardLen
		}

		for d.bytes+padBytes+shardLen > d.maxBytes && len(d.blocks) > 0 {
			if !d.evictOldestLocked() {
				break
			}
		}
		if d.bytes+padBytes+shardLen > d.maxBytes {
			return
		}
		b = &fecBlock{count: count, shardLen: shardLen, shards: make([][]byte, n+k)}

		if count < n {
			pad := make([]byte, shardLen)
			for i := count; i < n; i++ {
				b.shards[i] = pad
				b.present++
			}
		}
		b.bytes = padBytes
		d.bytes += padBytes
		b.arrival = d.seq
		d.seq++
		d.blocks[blk] = b
		d.evictLocked()
	} else if b.count != count || b.shardLen != shardLen {
		return
	}
	if b.done || b.shards[slot] != nil {
		return
	}
	if d.bytes+shardLen > d.maxBytes {
		if typ == fecTypeData {
			if b.gaveOut == nil {
				b.gaveOut = make([]bool, b.count)
			}
			b.gaveOut[slot] = true
			d.deliverShard(shard)
		}
		return
	}
	kept := make([]byte, shardLen)
	copy(kept, shard)
	b.shards[slot] = kept
	b.present++
	b.bytes += shardLen
	d.bytes += shardLen

	if typ == fecTypeData {
		d.deliverShard(shard)
	}
	if b.present < n {
		return
	}
	data, err := d.codec.Reconstruct(b.shards)
	if err != nil {
		return
	}
	b.done = true
	for i := 0; i < count; i++ {
		if b.shards[i] != nil {
			continue
		}
		if b.gaveOut != nil && b.gaveOut[i] {
			continue
		}
		d.deliverShard(data[i])
	}
}

func (d *fecDecoder) deliverShard(s []byte) {
	if len(s) < 2 {
		return
	}
	ln := int(binary.BigEndian.Uint16(s[:2]))
	if 2+ln <= len(s) {
		d.deliver(append([]byte(nil), s[2:2+ln]...))
	}
}

func (d *fecDecoder) evictLocked() {
	for len(d.blocks) > fecKeepBlocks {
		if !d.evictOldestLocked() {
			return
		}
	}
}

func (d *fecDecoder) evictOldestLocked() bool {
	var oldID uint32
	var oldB *fecBlock
	for id, b := range d.blocks {
		if oldB == nil || b.arrival < oldB.arrival {
			oldID, oldB = id, b
		}
	}
	if oldB == nil {
		return false
	}
	d.bytes -= oldB.bytes
	if d.bytes < 0 {
		d.bytes = 0
	}
	delete(d.blocks, oldID)
	return true
}
