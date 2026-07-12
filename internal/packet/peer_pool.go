package packet

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PeerPool rotates the client's DESTINATION endpoint across a list of candidate peer addresses, so a
// single blocked server IP does not kill the tunnel: a dead endpoint (the handshake never completes,
// or the carrier keeps failing) is BURNED and the pool advances to the next live one; a proactive
// timer also rotates on a schedule. This is the direct-transport analogue of the ws edge pool — it
// works at the dial/peer layer, before any transport framing, so tcp/udp/raw/flux all drive it the
// same way by swapping the destination they send to. Source-IP selection stays fixed (bindIP); only
// the destination rotates here.
//
// The pool never dead-ends: if every endpoint is burned it revives them all and starts over, so a
// transient outage that trips every candidate still recovers instead of stranding the tunnel.
type PeerPool struct {
	mu         sync.Mutex
	addrs      []string        // candidate peer endpoints ("ip" or "ip:port"), in operator order
	burned     map[string]bool // endpoints pulled from rotation (auto-burn)
	cur        int             // index of the active endpoint
	autoBurn   bool            // burn a failing endpoint (vs. only rotate past it)
	rotate     time.Duration   // proactive rotation interval (0 = failover-only)
	statusPath string          // status file the panel reads (empty = off)
}

// NewPeerPool builds a pool from the candidate endpoints. addrs must be non-empty (the caller only
// builds a pool when rotation is on with >1 endpoint; a 1-endpoint pool is harmless — it never
// rotates). rotate is the proactive interval; autoBurn drops a failing endpoint from rotation.
func NewPeerPool(addrs []string, autoBurn bool, rotate time.Duration, statusPath string) *PeerPool {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	return &PeerPool{addrs: cp, burned: make(map[string]bool), autoBurn: autoBurn, rotate: rotate, statusPath: statusPath}
}

// current returns the active endpoint (never empty for a non-empty pool).
func (p *PeerPool) current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[p.cur]
}

// size is the number of endpoints in the pool. It is fixed at construction, so no lock is needed.
func (p *PeerPool) size() int { return len(p.addrs) }

// nextLive advances cur to the next endpoint that is not burned, reviving all endpoints first if
// every one is burned (never dead-end). Caller holds the lock.
func (p *PeerPool) nextLive() {
	for i := 1; i <= len(p.addrs); i++ {
		idx := (p.cur + i) % len(p.addrs)
		if !p.burned[p.addrs[idx]] {
			p.cur = idx
			return
		}
	}
	// Everything is burned: revive all AND advance to the next endpoint (not the one we just left),
	// so a failover in the all-blocked state still MOVES — the caller sees moved=true and actually
	// re-points instead of hammering the same dead endpoint for another failover cycle before the
	// next fail() finally advances it.
	p.burned = make(map[string]bool)
	if len(p.addrs) > 1 {
		p.cur = (p.cur + 1) % len(p.addrs)
	}
}

// fail reports that the active endpoint looks dead. With auto-burn it is pulled from rotation; either
// way the pool advances to the next live endpoint and returns it (plus whether it actually moved).
func (p *PeerPool) fail() (addr string, moved bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addrs) < 2 { // nothing to rotate to
		return p.addrs[p.cur], false
	}
	prev := p.cur
	if p.autoBurn {
		p.burned[p.addrs[p.cur]] = true
	}
	p.nextLive()
	p.writeStatusLocked()
	return p.addrs[p.cur], p.cur != prev
}

// rotateOnce advances to the next live endpoint WITHOUT burning (the proactive-timer path). Returns
// the new endpoint and whether it moved (a 1-endpoint or all-but-one-burned pool may not move).
func (p *PeerPool) rotateOnce() (addr string, moved bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addrs) < 2 {
		return p.addrs[p.cur], false
	}
	prev := p.cur
	p.nextLive()
	if p.cur != prev {
		p.writeStatusLocked()
	}
	return p.addrs[p.cur], p.cur != prev
}

// succeeded clears a transient burn on the active endpoint after it connects (a burn is only ever a
// heuristic; a recovered endpoint should come back). Caller-visible so a transport can call it once
// its handshake completes.
func (p *PeerPool) succeeded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.burned[p.addrs[p.cur]] {
		delete(p.burned, p.addrs[p.cur])
		p.writeStatusLocked()
	}
}

// rotationController couples a client carrier's DESTINATION pool with an optional SOURCE pool and
// centralizes the failover/proactive policy, so every carrier (udp/tcp/raw/flux) drives rotation
// identically instead of re-deriving it. The carrier supplies its own rotate funcs (which actually
// swap the peer / the source IP); the controller only decides WHEN to call them.
//
// Policy: on a dead peer, burn+advance the destination; once the destination pool has cycled through
// every endpoint against the current source (destRot reaches the pool size — i.e. all were burned and
// revived), advance the source too, so a blocked source IP is walked off after its destinations are
// exhausted. A source-only pool (no dest pool) just advances the source. The proactive timer moves
// both pools together (a moving target on each side).
type rotationController struct {
	dst, src *PeerPool
	destRot  int
	rotate   time.Duration
	rotateAt time.Time
}

func newRotationController(dst, src *PeerPool) *rotationController {
	c := &rotationController{dst: dst, src: src}
	if dst != nil {
		c.rotate = dst.rotate
	}
	if src != nil && src.rotate > c.rotate {
		c.rotate = src.rotate
	}
	if c.rotate > 0 {
		c.rotateAt = time.Now().Add(c.rotate)
	}
	return c
}

// active reports whether any rotation is wired (either pool present).
func (c *rotationController) active() bool { return c != nil && (c.dst != nil || c.src != nil) }

// fail is called when the current peer looks dead. rotDst/rotSrc are the carrier's swap funcs.
func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) {
	if c.dst != nil {
		rotDst(false)
		c.destRot++
		if c.src != nil && c.dst.size() > 0 && c.destRot >= c.dst.size() {
			rotSrc(false) // every destination tried against this source — move the source
			c.destRot = 0
		}
		return
	}
	if c.src != nil {
		rotSrc(false)
	}
}

// success clears any transient burns after the carrier handshakes, and resets the dest-cycle counter.
func (c *rotationController) success() {
	c.destRot = 0
	if c.dst != nil {
		c.dst.succeeded()
	}
	if c.src != nil {
		c.src.succeeded()
	}
}

// proactive fires the timed rotation of BOTH pools when due (a signal-free moving target on each side).
func (c *rotationController) proactive(rotDst, rotSrc func(proactive bool), now time.Time) {
	if c.rotate <= 0 || c.rotateAt.IsZero() || !now.After(c.rotateAt) {
		return
	}
	if c.dst != nil {
		rotDst(true)
	}
	if c.src != nil {
		rotSrc(true)
	}
	c.rotateAt = now.Add(c.rotate)
}

type peerPoolStatus struct {
	Active  string   `json:"active"`
	Addrs   []string `json:"addrs"`
	Burned  []string `json:"burned"`
	Updated int64    `json:"updated_unix"`
}

// writeStatusLocked flushes the pool's live state to the status file the panel reads (which endpoint
// is active, which are burned), so the operator sees rotation/burns and can add fresh IPs. Caller
// holds the lock. Best-effort — a write error is non-fatal (the dataplane keeps running).
func (p *PeerPool) writeStatusLocked() {
	if p.statusPath == "" {
		return
	}
	burned := make([]string, 0, len(p.burned))
	for _, a := range p.addrs {
		if p.burned[a] {
			burned = append(burned, a)
		}
	}
	b, err := json.Marshal(peerPoolStatus{Active: p.addrs[p.cur], Addrs: p.addrs, Burned: burned, Updated: time.Now().Unix()})
	if err != nil {
		return
	}
	tmp := p.statusPath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, p.statusPath)
	}
}
