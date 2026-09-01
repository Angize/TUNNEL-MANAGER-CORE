package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

func newFecPair(fec bool, data, parity int, psk, name string, emit, deliver func([]byte)) (*fecEncoder, *fecDecoder) {
	if !fec {
		return nil, nil
	}
	key := newFecHdrMask(psk)
	enc, err := newFecEncoder(data, parity, key, emit)
	if err != nil {
		log.Printf("%s: FEC disabled (bad geometry %d+%d): %v", name, data, parity, err)
		return nil, nil
	}
	return enc, newFecDecoder(enc.codec, key, deliver)
}

type fecHdrMask struct{ blk cipher.Block }

func newFecHdrMask(psk string) fecHdrMask {
	k := sha256.Sum256([]byte("tnl-core-fec|v1|hdr|" + psk))
	b, err := aes.NewCipher(k[:16])
	if err != nil {
		panic(err)
	}
	return fecHdrMask{blk: b}
}

var fecScratch = sync.Pool{New: func() any { return new([2 * aes.BlockSize]byte) }}

func (m fecHdrMask) apply(hdr, body []byte) {
	buf := fecScratch.Get().(*[2 * aes.BlockSize]byte)
	n := copy(buf[:aes.BlockSize], body)
	for i := n; i < aes.BlockSize; i++ {
		buf[i] = 0
	}
	m.blk.Encrypt(buf[aes.BlockSize:], buf[:aes.BlockSize])
	for i := range hdr {
		hdr[i] ^= buf[aes.BlockSize+i]
	}
	fecScratch.Put(buf)
}

type fecHeader struct {
	typ                        byte
	blk                        uint32
	idx, n, k, count, shardLen int
}

func fecPutHdr(key fecHdrMask, h fecHeader, body []byte) []byte {
	p := make([]byte, fecHdrLen+len(body))
	p[0] = h.typ
	binary.BigEndian.PutUint32(p[1:5], h.blk)
	p[5] = byte(h.idx)
	p[6] = byte(h.n)
	p[7] = byte(h.k)
	p[8] = byte(h.count)
	binary.BigEndian.PutUint16(p[9:11], uint16(h.shardLen))
	copy(p[fecHdrLen:], body)
	key.apply(p[:fecHdrLen], p[fecHdrLen:])
	return p
}

func fecReadHdr(key fecHdrMask, pkt []byte) (fecHeader, []byte, bool) {
	if len(pkt) < fecHdrLen {
		return fecHeader{}, nil, false
	}
	var h [fecHdrLen]byte
	copy(h[:], pkt)
	body := pkt[fecHdrLen:]
	key.apply(h[:], body)
	return fecHeader{
		typ:      h[0],
		blk:      binary.BigEndian.Uint32(h[1:5]),
		idx:      int(h[5]),
		n:        int(h[6]),
		k:        int(h[7]),
		count:    int(h[8]),
		shardLen: int(binary.BigEndian.Uint16(h[9:11])),
	}, body, true
}

func fecTag(enc *fecEncoder, frame []byte) []byte {
	if enc == nil {
		return frame
	}
	return fecPutHdr(enc.key, fecHeader{typ: fecTypePass}, frame)
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
	key   fecHdrMask
	emit  func([]byte)

	mu     sync.Mutex
	block  uint32
	shards [][]byte
	timer  *time.Timer
	closed bool
}

func newFecEncoder(n, k int, key fecHdrMask, emit func([]byte)) (*fecEncoder, error) {
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil, err
	}
	return &fecEncoder{codec: c, n: n, k: k, key: key, emit: emit}, nil
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
	hdr := func(typ byte, idx int) fecHeader {
		return fecHeader{typ: typ, blk: blk, idx: idx, n: e.n, k: e.k, count: count, shardLen: shardLen}
	}

	for i := 0; i < count; i++ {
		e.emit(fecPutHdr(e.key, hdr(fecTypeData, i), queued[i]))
	}

	kEff := (e.k*count + e.n - 1) / e.n
	for i := 0; i < kEff; i++ {
		e.emit(fecPutHdr(e.key, hdr(fecTypeParity, i), parity[i]))
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
	key      fecHdrMask
	codec    *fecCodec
	deliver  func([]byte)

	resetPending atomic.Bool
}

func newFecDecoder(c *fecCodec, key fecHdrMask, deliver func([]byte)) *fecDecoder {
	return &fecDecoder{blocks: map[uint32]*fecBlock{}, maxBytes: fecMaxBytes,
		n: c.n, k: c.k, key: key, codec: c, deliver: deliver}
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
	h, shard, ok := fecReadHdr(d.key, pkt)
	if !ok {
		return
	}
	switch h.typ {
	case fecTypePass:
		if h.blk != 0 || h.idx != 0 || h.n != 0 || h.k != 0 || h.count != 0 || h.shardLen != 0 || len(shard) < 1 {
			return
		}
		d.deliver(shard)
		return
	case fecTypeData, fecTypeParity:
	default:
		return
	}
	typ, blk, idx := h.typ, h.blk, h.idx
	n, k, count := h.n, h.k, h.count
	shardLen := h.shardLen
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
		if typ == fecTypeData {
			d.deliverShard(shard)
		}
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
