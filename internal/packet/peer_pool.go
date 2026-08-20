package packet

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type PeerPool struct {
	burns      atomic.Uint64
	mu         sync.Mutex
	writeMu    sync.Mutex
	addrs      []string
	health     healthSet
	cur        int
	rotate     time.Duration
	statusPath string

	pinKey   string
	pinTries int

	pinTook *healthRec

	chosen string
	now    func() int64

	axis string
	ev   func(kind, code, detail string)
}

// Which half of the matrix this pool is, and where its events go. The pool cannot know either: the
// carrier owns the status file and decides whether it is the destination axis or the source one.
func (p *PeerPool) setEvent(axis string, ev func(kind, code, detail string)) {
	p.mu.Lock()
	p.axis, p.ev = axis, ev
	p.mu.Unlock()
}

func (p *PeerPool) emit(code, reason string) {
	p.mu.Lock()
	axis, ev := p.axis, p.ev
	p.mu.Unlock()
	if ev != nil {
		ev("pool", code, axis+":"+reason)
	}
}

// One way a pin ends, whatever ended it. `matched` runs under the lock and decides -- and may count,
// which is why it cannot be a plain bool.
func (p *PeerPool) dropPin(reason string, matched func() bool) bool {
	p.mu.Lock()
	hit := matched()
	if hit {
		p.restorePinTookLocked()
		p.pinKey, p.pinTries = "", 0
	}
	p.mu.Unlock()
	if hit {
		p.writeStatus()
		p.emit("pin_dropped", reason)
	}
	return hit
}

func NewPeerPool(addrs []string, rotate time.Duration, statusPath string) *PeerPool {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	p := &PeerPool{addrs: cp, rotate: rotate,
		statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.health = newHealthSet(&p.now)
	p.writeStatus()
	return p
}

func (p *PeerPool) current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked()
}

func (p *PeerPool) commitLocked(idx int) string {
	p.cur = idx
	p.chosen = p.addrs[idx]
	return p.chosen
}

func (p *PeerPool) pickLocked(idx int) string {
	p.cur = idx
	p.chosen = ""
	return p.addrs[idx]
}

func (p *PeerPool) currentLocked() string {
	if p.pinKey != "" {
		for idx, a := range p.addrs {
			if a == p.pinKey {
				return p.pickLocked(idx)
			}
		}
		p.pinKey = ""
	}
	n := len(p.addrs)

	if p.chosen != "" && p.addrs[p.cur] == p.chosen {
		return p.chosen
	}

	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if p.health.healthy(p.addrs[idx]) {
			return p.pickLocked(idx)
		}
	}

	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if p.health.due(p.addrs[idx]) {
			return p.pickLocked(idx)
		}
	}

	return p.pickLocked(p.bestIdxLocked(-1))
}

func (p *PeerPool) eligibleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.health.countEligible(p.addrs)
}

func (p *PeerPool) activeIdx() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur
}

func (p *PeerPool) size() int { return len(p.addrs) }

func (p *PeerPool) all() []string {
	out := make([]string, len(p.addrs))
	copy(out, p.addrs)
	return out
}

func (p *PeerPool) tierLocked(addr string) (tier int, next int64) { return p.health.tier(addr) }

func (p *PeerPool) bestIdxLocked(except int) int {
	best := -1
	var bt int
	var bn int64
	for i := range p.addrs {
		if i == except {
			continue
		}
		t, n := p.tierLocked(p.addrs[i])
		if best == -1 || t < bt || (t == bt && n < bn) {
			best, bt, bn = i, t, n
		}
	}
	if best == -1 {
		return except
	}
	return best
}

func (p *PeerPool) burnLocked(addr string) bool {
	return p.health.burn(addr)
}

func (p *PeerPool) burnCount() uint64 { return p.burns.Load() }

func retestBackoff(r *healthRec, now int64) {
	if r.state == stateDead {
		r.nextRetest = now + deadRetest
		return
	}
	r.fails++
	if r.fails >= len(suspectBackoff) {
		r.state = stateDead
		r.nextRetest = now + deadRetest
		return
	}
	r.nextRetest = now + suspectBackoff[r.fails]
}

func (p *PeerPool) advanceFailLocked() {
	n := len(p.addrs)
	for k := 1; k <= n; k++ {
		idx := (p.cur + k) % n
		if p.health.healthy(p.addrs[idx]) {
			p.commitLocked(idx)
			return
		}
	}
	for k := 1; k <= n; k++ {
		idx := (p.cur + k) % n
		if p.health.due(p.addrs[idx]) {
			p.commitLocked(idx)
			return
		}
	}
	if best := p.bestIdxLocked(p.cur); best != p.cur && p.betterLocked(best, p.cur) {
		p.commitLocked(best)
	}
}

func (p *PeerPool) betterLocked(a, b int) bool {
	at, an := p.tierLocked(p.addrs[a])
	bt, bn := p.tierLocked(p.addrs[b])
	return at < bt || (at == bt && an < bn)
}

func (p *PeerPool) advanceEligibleLocked() bool {
	n := len(p.addrs)
	for k := 1; k <= n; k++ {
		idx := (p.cur + k) % n
		if idx == p.cur {
			break
		}
		if p.health.eligible(p.addrs[idx]) {
			p.commitLocked(idx)
			return true
		}
	}
	return false
}

func (p *PeerPool) fail() (addr string, moved bool) {
	p.mu.Lock()

	if len(p.addrs) < 2 || p.pinnedLocked() {
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	prev := p.cur
	if p.burnLocked(p.addrs[p.cur]) {
		p.burns.Add(1)
	}
	p.advanceFailLocked()
	a := p.addrs[p.cur]
	moved = p.cur != prev
	p.mu.Unlock()
	p.writeStatus()
	return a, moved
}

func (p *PeerPool) rotateOnce() (addr string, moved bool) {
	p.mu.Lock()
	if len(p.addrs) < 2 || p.pinnedLocked() {
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	moved = p.advanceEligibleLocked()
	a := p.addrs[p.cur]
	p.mu.Unlock()
	if moved {
		p.writeStatus()
	}
	return a, moved
}

func (p *PeerPool) nextEndpoint(proactive bool) (addr string, moved bool) {
	if proactive {
		return p.rotateOnce()
	}
	return p.fail()
}

func (p *PeerPool) keepCursorOn(addr string) {
	if p == nil || addr == "" {
		return
	}
	p.mu.Lock()
	moved := false
	if p.addrs[p.cur] != addr {
		for idx, a := range p.addrs {
			if a == addr {
				p.commitLocked(idx)
				moved = true
				break
			}
		}
	}
	p.mu.Unlock()
	if moved {
		p.writeStatus()
	}
}

func (p *PeerPool) rejectCandidate(prev string) {
	p.mu.Lock()
	if bad := p.addrs[p.cur]; bad != prev {
		p.burnLocked(bad)
	}
	back := false
	for idx, a := range p.addrs {
		if a == prev {
			p.commitLocked(idx)
			back = true
			break
		}
	}
	if !back {

		p.advanceFailLocked()
	}
	p.mu.Unlock()
	p.writeStatus()
}

func (p *PeerPool) clearBurn(addr string) bool {
	p.mu.Lock()
	cleared := p.health.clear(addr)
	p.mu.Unlock()
	if cleared {
		p.writeStatus()
	}
	return cleared
}

func (p *PeerPool) restoreAll() {
	p.mu.Lock()
	cleared := p.health.clearAll()
	p.mu.Unlock()
	if cleared {
		p.writeStatus()
	}
}

func (p *PeerPool) probeAllNow() {
	p.mu.Lock()
	p.health.probeAllNow()
	p.mu.Unlock()
	p.writeStatus()
}

func (p *PeerPool) selectEntry(key string) bool {
	p.mu.Lock()
	ok := false
	for idx, a := range p.addrs {
		if a == key {

			if p.pinKey != "" && p.pinKey != key {
				p.restorePinTookLocked()
			}
			p.pinKey, p.pinTries = key, 0
			p.pinTook = p.health.rec(key)
			p.health.clear(key)
			p.pickLocked(idx)
			ok = true
			break
		}
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
	}
	return ok
}

func (p *PeerPool) pinLandedOn(addr string) {
	p.mu.Lock()
	changed := p.pinnedLocked() && p.pinKey == addr
	if changed {

		p.pinKey, p.pinTries, p.pinTook = "", 0, nil
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

func (p *PeerPool) restorePinTookLocked() {
	if p.pinTook != nil && p.pinKey != "" {
		p.health.recs[p.pinKey] = p.pinTook
	}
	p.pinTook = nil
}

func (p *PeerPool) pinAttemptFailed(addr string) {
	p.dropPin("cannot-land", func() bool {
		if p.pinKey == "" || p.pinKey != addr {
			return false
		}
		p.pinTries++
		return p.pinTries >= pinFailRelease
	})
}

func (p *PeerPool) pinCannotLand(key string) bool {
	return p.dropPin("cannot-land", func() bool { return p.pinnedLocked() && p.pinKey == key })
}

func (p *PeerPool) releasePin() {
	p.dropPin("tun-probe", func() bool { return p.pinKey != "" })
}

func (p *PeerPool) pinnedLocked() bool { return p.pinKey != "" }

func (p *PeerPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinnedLocked()
}

func (p *PeerPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

type poolCmd struct {
	Cmd  string `json:"cmd"`
	Key  string `json:"key"`
	Src  string `json:"src"`
	Kind string `json:"kind"`
	IP   string `json:"ip"`
	SNI  string `json:"sni"`

	Epoch int64 `json:"epoch"`
}

func staleVerdict(c poolCmd, epoch int64) bool {
	return (c.Cmd == cmdOK || c.Cmd == cmdFail) && c.Epoch != epoch
}

func readPoolCmd(path string) (c poolCmd, ok bool) {
	if path == "" {
		return c, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, false
	}
	os.Remove(path)
	if json.Unmarshal(data, &c) != nil || (c.Key == "" && c.Cmd == "") {
		return poolCmd{}, false
	}
	return c, true
}

const cmdFail = "fail"

const cmdOK = "ok"

func (p *PeerPool) readCmd() (poolCmd, bool) { return readPoolCmd(p.cmdPath()) }

type pinnable interface {
	isPinned() bool
	releasePin()
}

// The digit a fail condemns every round.
type lowAxis interface {
	eligibleCount() int
	burnCount() uint64
	restoreAll()
}

// The digit that turns once a whole row of the low one has been tried.
type highAxis interface {
	activeIdx() int
}

type walkPolicy struct {
	mu       sync.Mutex
	pinFails int
	od       odometer
	pins     []pinnable
	low      lowAxis
	high     highAxis
}

func (w *walkPolicy) pinnedLocked() bool {
	for _, p := range w.pins {
		if p.isPinned() {
			return true
		}
	}
	return false
}

func (w *walkPolicy) hasLow() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.low != nil
}

func (w *walkPolicy) reset() {
	w.mu.Lock()
	w.pinFails = 0
	w.mu.Unlock()
	w.od.restart()
}

func (w *walkPolicy) walk(rotLow, rotHigh func(proactive bool)) (stepped, lowBurned bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pinnedLocked() {

		w.pinFails++
		if w.pinFails < pinFailRelease {
			return false, false
		}
		w.pinFails = 0
		for _, p := range w.pins {
			p.releasePin()
		}

	} else {
		w.pinFails = 0
	}
	switch {
	case w.low != nil:

		lap := w.od.failed(w.low.eligibleCount)
		before := w.low.burnCount()
		rotLow(false)
		lowBurned = w.low.burnCount() != before
		if w.high != nil && lap {
			at := w.high.activeIdx()
			rotHigh(false)
			if w.high.activeIdx() != at {
				w.low.restoreAll()
			}
		}
		return true, lowBurned
	case w.high != nil:
		rotHigh(false)
		return true, false
	}
	return false, false
}

type rotationController struct {
	walkPolicy
	dst, src *PeerPool
	verdict  string
	port     portRung
	session  sessionRung
	rotate   time.Duration
	rotateAt time.Time
}

func newRotationController(dst, src *PeerPool) *rotationController {
	c := &rotationController{}
	c.bind(dst, src)
	if c.rotate > 0 {
		c.rotateAt = time.Now().Add(c.rotate)
	}
	return c
}

// The destination is the digit a fail condemns; the source turns once every destination has been tried
// against it. One place decides that, so a pool can never be wired to the policy the wrong way round.
func (c *rotationController) bind(dst, src *PeerPool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dst, c.src = dst, src
	c.pins, c.low, c.high, c.rotate = nil, nil, nil, 0
	if dst != nil {
		c.pins = append(c.pins, dst)
		c.low = dst
		c.rotate = dst.rotate
	}
	if src != nil {
		c.pins = append(c.pins, src)
		c.high = src
		if src.rotate > c.rotate {
			c.rotate = src.rotate
		}
	}
}

func (c *rotationController) active() bool { return c != nil && (c.dst != nil || c.src != nil) }

func (c *rotationController) setVerdict(path string) { c.verdict = path }

func (c *rotationController) polls() bool {
	return c != nil && (c.active() || c.verdict != "")
}

func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) (dstBurned bool) {

	if c.port.try() {
		return false
	}

	if c.session.try() {
		return false
	}
	moved, burned := c.walk(rotDst, rotSrc)
	if moved {
		c.port.restart()
	}
	return burned
}

func (c *rotationController) success() {
	c.reset()
	c.port.restart()
	c.session.restart()
}

func (c *rotationController) proactive(rotDst, rotSrc func(proactive bool), now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rotate <= 0 || c.rotateAt.IsZero() || !now.After(c.rotateAt) {
		return
	}
	if c.pinnedLocked() {
		c.rotateAt = now.Add(c.rotate)
		return
	}
	c.rotateAt = now.Add(c.rotate)
	if c.dst == nil {
		if c.src != nil {
			rotSrc(true)
		}
		return
	}
	before := c.dst.activeIdx()
	rotDst(true)
	if lap := c.od.beat(c.dst.activeIdx() != before, c.dst.eligibleCount); c.src != nil && lap {
		rotSrc(true)
	}
}

func (c *rotationController) pollPins(applyDst, applySrc func(), rotDst, rotSrc func(proactive bool),
	ev func(kind, code, detail string), pathEpoch func() int64) {
	if cmd, ok := readPoolCmd(c.verdict); ok {
		c.judge(cmd, rotDst, rotSrc, ev, pathEpoch())
	}

	if c.dst != nil {
		if cmd, ok := c.dst.readCmd(); ok && cmd.Key != "" && c.dst.selectEntry(cmd.Key) {
			applyDst()
		}
	}
	if c.src != nil {

		if cmd, ok := c.src.readCmd(); ok && cmd.Key != "" && c.src.selectEntry(cmd.Key) {
			applySrc()
		}
	}
}

func (c *rotationController) judge(cmd poolCmd, rotDst, rotSrc func(proactive bool),
	ev func(kind, code, detail string), epoch int64) {
	switch {
	case staleVerdict(cmd, epoch):

		log.Printf("core: dropping a tun-probe verdict for path epoch %d — the carrier is on %d now",
			cmd.Epoch, epoch)
	case cmd.Cmd == cmdOK:

		c.success()

		if c.dst != nil && cmd.Key != "" && c.dst.clearBurn(cmd.Key) && ev != nil {
			ev("heal", "peer-retest", cmd.Key)
		}
		if c.src != nil && cmd.Src != "" && c.src.clearBurn(cmd.Src) && ev != nil {
			ev("heal", "src-retest", cmd.Src)
		}
	case cmd.Cmd == cmdFail:

		if c.fail(rotDst, rotSrc) {
			log.Printf("core: destination %s failed by the node's tun probe — burning and advancing", cmd.Key)
			if ev != nil {
				ev("burn", "tun-probe", "ip:"+cmd.Key)
			}
		}
	}
}

type peerPoolStatus struct {
	Active  string         `json:"active"`
	Addrs   []string       `json:"addrs"`
	Health  []healthStatus `json:"health"`
	Pin     string         `json:"pin"`
	Updated int64          `json:"updated_unix"`
}

func (p *PeerPool) writeStatus() {
	if p.statusPath == "" {
		return
	}

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	health := make([]healthStatus, 0, len(p.addrs))
	for _, a := range p.addrs {
		hs := healthStatus{Key: a, Kind: "ip", State: "healthy"}
		if r := p.health.rec(a); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		health = append(health, hs)
	}
	st := peerPoolStatus{Active: p.addrs[p.cur], Addrs: append([]string(nil), p.addrs...),
		Health: health, Pin: p.pinKey, Updated: time.Now().Unix()}
	p.mu.Unlock()
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	writeFileAtomic(p.statusPath, data, 0o644)
}
