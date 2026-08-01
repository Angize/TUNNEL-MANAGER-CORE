// Wire layer for FEC on the datagram carriers: it turns the stream of sealed frames
// into FEC blocks (n data + k parity) on send, and reassembles+reconstructs them on
// receive. It sits between the carrier's frame layer and its socket, so both flux and
// the udp carrier can share it.
//
// When FEC is on, EVERY packet carries a 1-byte type tag so the receiver can route it:
//
//	type 0  passthrough : [0][frame]                          (ping/pong/handshake — not blocked)
//	type 1  data shard  : [1][hdr][shard]  shard = [len:2][sealed] zero-padded to shardLen
//	type 2  parity shard: [2][hdr][shard]  shard = RS parity bytes
//	hdr = [block:4][idx:1][n:1][k:1][count:1][shardLen:2]     (count = real data shards in the block)
//
// A block is flushed when it fills (n data frames) or a short timer fires; a partial
// block is zero-padded to n for the RS math but only its `count` real shards are sent
// (the receiver synthesizes the pad shards as zeros).
//
// The code is SYSTEMATIC, so a data shard already carries its own payload: the receiver
// delivers each one the moment it arrives and uses the parity only to fill the gaps,
// reconstructing as soon as any n of the block's n+k shards are in. Nothing a receiver
// physically got is ever held hostage to the rest of its block.
package packet

import (
	"encoding/binary"
	"log"
	"sync"
	"time"
)

// newFecPair builds the encoder/decoder a datagram carrier needs to run FEC, or
// (nil, nil) when fec is off or the geometry is bad (logged, so the carrier just
// runs without FEC rather than failing). emit sends one ready wire packet (the
// carrier wraps + transmits it to the peer); deliver receives each recovered frame
// (the carrier feeds it back into its normal crypto/clear path). This keeps the
// three datagram carriers (udp, raw, flux) sharing one FEC wiring.
func newFecPair(fec bool, data, parity int, name string, emit, deliver func([]byte)) (*fecEncoder, *fecDecoder) {
	if !fec {
		return nil, nil
	}
	enc, err := newFecEncoder(data, parity, emit)
	if err != nil {
		log.Printf("%s: FEC disabled (bad geometry %d+%d): %v", name, data, parity, err)
		return nil, nil
	}
	return enc, newFecDecoder(deliver)
}

// fecTag prepends the passthrough type tag to a control/handshake frame when enc is
// non-nil (FEC on), so the peer's decoder forwards it straight through instead of
// parsing it as a shard. With FEC off it returns the frame unchanged.
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
	fecHdrLen     = 1 + 4 + 1 + 1 + 1 + 1 + 2 // type + block,idx,n,k,count,shardLen
	fecFlushDelay = 15 * time.Millisecond     // flush a partial block after this idle gap
	fecKeepBlocks = 64                        // receiver: how many recent blocks to retain
	fecMaxBytes   = 64 << 20                  // receiver: cap total bytes buffered across live blocks (anti-amplification)

	// fecMaxCodecs caps the number of DISTINCT (n,k) Reed-Solomon codecs the decoder caches. A real
	// encoder uses one fixed (n,k) (or a tiny handful), but fecDecoder.input runs BEFORE peer auth, so
	// an unauthenticated peer can spray unique (n,k) block headers; each cached codec pins a k×n
	// GF(256) matrix that fecMaxBytes does NOT budget, so an unbounded cache is a memory-exhaustion
	// DoS (~32k valid pairs -> hundreds of MB). 64 covers any legitimate config with wide headroom.
	// The cap is enforced by evicting the least-recently-used entry, never by refusing to cache —
	// see codec().
	fecMaxCodecs = 64

	// fecMaxShardLen caps the shard length a peer may declare in a block header. A real
	// shard is one sealed frame ([len:2]+ciphertext) zero-padded to the block's largest
	// shard, so it is MTU-bounded — well under this even for jumbo frames. Rejecting a
	// larger shardLen blocks a forged block with maximal geometry (n=255, count=1,
	// shardLen~65495) from reserving (n-count)*shardLen ~= 16 MB of pad out of a single
	// ~64 KB packet; a few such never-completed blocks could otherwise pin the whole
	// fecMaxBytes budget until process exit (amplification DoS). 16 KiB never rejects a
	// legitimate shard.
	fecMaxShardLen = 16 << 10
)

// fecEncoder buffers sealed data frames and emits FEC block packets via emit().
type fecEncoder struct {
	codec *fecCodec
	n, k  int
	emit  func([]byte) // sends one ready wire packet (the carrier wraps + transmits it)

	mu     sync.Mutex
	block  uint32
	shards [][]byte // pending data payloads, each already [len:2][sealed]
	timer  *time.Timer
	closed bool // set by Close(): no more flushes/emits (a late timer callback becomes a no-op)
}

func newFecEncoder(n, k int, emit func([]byte)) (*fecEncoder, error) {
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil, err
	}
	return &fecEncoder{codec: c, n: n, k: k, emit: emit}, nil
}

// Close stops the flush timer and marks the encoder closed, so a timer callback that already
// fired and is blocked on e.mu (or a later addData) cannot emit a shard on an
// already-closed carrier socket. Idempotent.
func (e *fecEncoder) Close() {
	e.mu.Lock()
	e.closed = true
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.mu.Unlock()
}

// addData queues one sealed data frame; flushes the block when it fills, else arms the timer.
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

// flushLocked encodes and emits the pending block. Caller holds e.mu.
func (e *fecEncoder) flushLocked() {
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	if e.closed {
		return // a late timer callback after Close(): do not emit on a closed socket
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
	for i := 0; i < count; i++ { // only the real data shards go on the wire
		e.emit(append(hdr(fecTypeData, i), data[i]...))
	}
	// Parity scales with what the block actually carries. A partial block puts `count` data
	// shards on the wire, not n — the receiver synthesizes the (n-count) pad shards as zeros —
	// so emitting all k parity costs k/count, not the configured k/n. At the default 10+3 that
	// is 300% overhead on every single-frame flush, i.e. on every tunnel under ~667 pps, where
	// the panel promises ۳۰٪. kEff = ceil(k*count/n) is the SMALLEST parity count that still
	// holds the configured erasure ratio (kEff/(count+kEff) >= k/(n+k) reduces to kEff >= k*count/n),
	// and it is exactly k when the block is full, so a saturated tunnel is untouched.
	// NOT a wire change: the header still declares the configured k, so the decoder is unchanged
	// and simply never sees the parity shards we did not send — they are erasures like any other.
	kEff := (e.k*count + e.n - 1) / e.n
	for i := 0; i < kEff; i++ {
		e.emit(append(hdr(fecTypeParity, i), parity[i]...))
	}
}

// fecBlock accumulates the shards of one block until it can be reconstructed.
type fecBlock struct {
	n, k, count, shardLen int
	shards                [][]byte // len n+k; nil = missing
	present               int
	bytes                 int    // bytes buffered for this block (for the decoder byte budget)
	arrival               uint64 // decoder-local insertion order; the eviction key
	done                  bool
	// gaveOut marks data slots [0,count) that were handed to deliver() but NOT retained, because the
	// decoder's byte budget was exhausted when they arrived. They are neither present (parity may
	// still have to reconstruct the block around them) nor owed (the payload already went out), so
	// the reconstruct loop must skip them or the peer gets the same frame twice. nil until one
	// happens, which on a healthy tunnel is never.
	gaveOut []bool
}

// fecCodecEntry is one cached Reed-Solomon codec plus the decoder-local tick at which it was
// last handed out — the LRU key.
type fecCodecEntry struct {
	c    *fecCodec
	used uint64
}

// fecDecoder reassembles blocks and delivers sealed frames via deliver(): each data shard as
// it arrives, then the ones parity recovered once the block completes.
type fecDecoder struct {
	mu        sync.Mutex
	blocks    map[uint32]*fecBlock
	seq       uint64                 // monotonic arrival counter stamped on each new block (the eviction key)
	bytes     int                    // total bytes buffered across all live blocks (budgeted by maxBytes)
	maxBytes  int                    // the byte budget; fecMaxBytes in production, lowered by tests
	codecs    map[int]*fecCodecEntry // keyed by n<<8|k, bounded by fecMaxCodecs, LRU-evicted
	codecTick uint64                 // monotonic use counter stamped on each codec hand-out (the LRU key)
	deliver   func([]byte)           // called with each sealed frame, exactly once, in arrival order
}

func newFecDecoder(deliver func([]byte)) *fecDecoder {
	return &fecDecoder{blocks: map[uint32]*fecBlock{}, codecs: map[int]*fecCodecEntry{},
		maxBytes: fecMaxBytes, deliver: deliver}
}

// codec returns the Reed-Solomon codec for one block geometry, building and caching it on first
// use. Caller holds d.mu.
//
// The cache must stay bounded because input runs pre-auth: an unauthenticated peer can name any
// (n,k) it likes and each cached codec pins a k×n GF(256) matrix that fecMaxBytes does not budget.
// But a bound alone was a PERMANENT poison — nothing ever pruned d.codecs, so one cheap burst of
// fecMaxCodecs distinct geometries, sent before the tunnel ever carries traffic, locked the cache
// shut and the real geometry could never be cached again for the life of the process. FEC recovery
// was then off for good, silently, with the panel still showing it on.
//
// Evicting the least-recently-used entry keeps the same bound and makes the attack unstickable:
// the worst a sprayer can achieve is forcing the live geometry's codec to be rebuilt, which is one
// k×n table of GF(256) divisions — exactly k*n of them (newFECCodec), so at the panel's 10+3 that is
// 30, and at the widest geometry the codec itself accepts (n+k <= 256) it peaks around 16k. Still
// trivial, which is why the conclusion holds; "at most 256" was simply the wrong number.
func (d *fecDecoder) codec(n, k int) *fecCodec {
	key := n<<8 | k
	d.codecTick++
	if e := d.codecs[key]; e != nil {
		e.used = d.codecTick
		return e.c
	}
	if len(d.codecs) >= fecMaxCodecs {
		d.evictLRUCodecLocked()
	}
	c, err := newFECCodec(n, k)
	if err != nil {
		return nil
	}
	d.codecs[key] = &fecCodecEntry{c: c, used: d.codecTick}
	return c
}

// evictLRUCodecLocked drops the single least-recently-used cached codec, making room for one more.
// Caller holds d.mu.
func (d *fecDecoder) evictLRUCodecLocked() {
	var oldKey int
	var oldE *fecCodecEntry
	for key, e := range d.codecs {
		if oldE == nil || e.used < oldE.used {
			oldKey, oldE = key, e
		}
	}
	if oldE != nil {
		delete(d.codecs, oldKey)
	}
}

// input consumes one received wire packet (already stripped of the carrier header).
func (d *fecDecoder) input(pkt []byte) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] {
	case fecTypePass:
		if len(pkt) < 2 {
			return // drop a bare 1-byte passthrough; hygiene only (the downstream AEAD is the real auth gate)
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
	if n < 1 || k < 1 || n+k > 256 || count < 1 || count > n || shardLen < 2 || shardLen > fecMaxShardLen || len(shard) != shardLen {
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
		return // a data shard's index must fall inside the real data shards (the encoder only emits idx<count)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	b := d.blocks[blk]
	if b == nil {
		// Reserve this block's pad shards (plus the incoming shard) up front and refuse
		// if the decoder's total buffered bytes would exceed the budget: an unauthenticated
		// peer must not be able to pin ~n*shardLen*fecKeepBlocks of RAM (amplification DoS).
		padBytes := (n - count) * shardLen
		// Byte-pressure eviction: a few large-geometry partial blocks can drive d.bytes to
		// fecMaxBytes with fewer than fecKeepBlocks blocks, so the count-based evictLocked never
		// fires and every new block is refused below — permanently disabling FEC recovery for an
		// unauthenticated peer (pre-auth DoS). Drop oldest-by-arrival blocks until there is room
		// (or nothing left to evict), THEN refuse only if still over budget.
		for d.bytes+padBytes+shardLen > d.maxBytes && len(d.blocks) > 0 {
			if !d.evictOldestLocked() {
				break
			}
		}
		if d.bytes+padBytes+shardLen > d.maxBytes {
			return
		}
		b = &fecBlock{n: n, k: k, count: count, shardLen: shardLen, shards: make([][]byte, n+k)}
		// pad shards [count, n) are known-zero and count as present for the RS math.
		for i := count; i < n; i++ {
			b.shards[i] = make([]byte, shardLen)
			b.present++
		}
		b.bytes = padBytes
		d.bytes += padBytes
		b.arrival = d.seq
		d.seq++
		d.blocks[blk] = b
		d.evictLocked() // keep only the most-recently-inserted fecKeepBlocks
	} else if b.n != n || b.k != k || b.count != count || b.shardLen != shardLen {
		// A shard whose geometry disagrees with the block already created for this id.
		// Dropping it is what prevents an out-of-range slot (slot is bounded only by the
		// incoming header's n+k, not by len(b.shards)) and mixed shard lengths — either of
		// which is a remote, pre-crypto out-of-range panic that crashes the root process.
		return
	}
	if b.done || b.shards[slot] != nil {
		return
	}
	if d.bytes+shardLen > d.maxBytes {
		// Over the decoder's byte budget, so this shard cannot be RETAINED — but a data shard is its
		// own payload (the code is systematic) and deliverShard copies straight out of the wire buffer,
		// so handing it on costs no storage whatsoever. Only the b.shards[slot] retention does.
		// Returning outright made the file-header promise above ("nothing a receiver physically got is
		// ever held hostage to the rest of its block") false in exactly the case it was written for:
		// under a pre-auth amplification flood, packets that arrived intact were thrown away by the FEC
		// layer instead of being handed on — with FEC on, the decoder is the ONLY path these frames
		// have, so that is a hard hole in the stream with no log, no counter and no event.
		//
		// No new pre-auth exposure: deliver() is already reached unbudgeted by every fecTypePass packet
		// above, and by every in-budget data shard. gaveOut records the hand-over so the reconstruct
		// loop below does not deliver the same frame a second time if parity later fills this slot.
		if typ == fecTypeData {
			if b.gaveOut == nil {
				b.gaveOut = make([]bool, b.count)
			}
			b.gaveOut[slot] = true
			d.deliverShard(shard)
		}
		return
	}
	b.shards[slot] = append([]byte(nil), shard...)
	b.present++
	b.bytes += shardLen
	d.bytes += shardLen
	// A data shard IS its payload (the code is systematic), so hand it over the moment it
	// arrives instead of holding it until the whole block can be reconstructed. Holding it is
	// what made a block that never completes cost 100% of its payload rather than only the
	// shards that were really lost: with FEC on, tunToNet never writes a frame itself, so the
	// decoder is the ONLY path these frames have, and a discarded block is a hard hole in the
	// stream. Above the geometry's repair budget (~17% loss at 10+3) that made FEC WORSE than
	// no FEC at all. Delivering here also drops the up-to-a-whole-block delay the receiver used
	// to add even when nothing was lost. Delivery order becomes wire-arrival order, i.e. exactly
	// what the same carrier does with FEC off; parity fills the gaps below.
	if typ == fecTypeData {
		d.deliverShard(shard)
	}
	if b.present < n {
		return
	}
	c := d.codec(n, k)
	if c == nil {
		return
	}
	data, err := c.Reconstruct(b.shards)
	if err != nil {
		return
	}
	b.done = true
	for i := 0; i < count; i++ {
		if b.shards[i] != nil {
			continue // this one arrived intact and was already delivered above
		}
		if b.gaveOut != nil && b.gaveOut[i] {
			continue // arrived and was delivered, but the byte budget refused to retain it
		}
		d.deliverShard(data[i]) // recovered from parity — the only ones still owed
	}
}

// deliverShard unwraps one data shard ([len:2][sealed], zero-padded to shardLen) and hands the
// sealed frame to the carrier. A shard too short to hold its own length prefix, or one whose
// declared length overruns it, is dropped: input runs pre-auth, so this is reached with attacker-
// chosen bytes and the downstream AEAD is the real gate.
func (d *fecDecoder) deliverShard(s []byte) {
	if len(s) < 2 {
		return
	}
	ln := int(binary.BigEndian.Uint16(s[:2]))
	if 2+ln <= len(s) {
		d.deliver(append([]byte(nil), s[2:2+ln]...))
	}
}

// evictLocked bounds the number of live blocks by dropping the OLDEST-INSERTED ones. Eviction
// is keyed on a decoder-local arrival counter, NOT the wire block id, so (a) a peer cannot pin the
// eviction horizon with a forged block number — a single packet with block=0xFFFFFFFF used to make
// every real (small-id) block satisfy the old maxSeen-distance test and get evicted forever — and
// (b) there is no uint32 block-id wraparound hazard. Caller holds d.mu.
func (d *fecDecoder) evictLocked() {
	for len(d.blocks) > fecKeepBlocks {
		if !d.evictOldestLocked() {
			return
		}
	}
}

// evictOldestLocked drops the single OLDEST-INSERTED block (keyed on the decoder-local arrival
// counter, not the wire block id) and returns true if one was removed. Shared by the count-based
// evictLocked and the byte-pressure eviction on the new-block path, so both use the same
// oldest-by-arrival selection. d.bytes is decremented by the dropped block and clamped so it can
// never go negative. Caller holds d.mu.
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
