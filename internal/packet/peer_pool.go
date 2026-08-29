package packet

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type PeerPool struct {
	burns  atomic.Uint64
	mu     sync.Mutex
	addrs  []string
	health healthSet
	cur    int
	rotate time.Duration

	pinKey  string
	pinTook *healthRec

	chosen string
	now    func() int64

	axis  string
	ev    func(kind, code, detail string)
	flush func()
}

func (p *PeerPool) attach(axis string, ev func(kind, code, detail string), flush func()) {
	p.mu.Lock()
	p.axis, p.ev, p.flush = axis, ev, flush
	p.mu.Unlock()
	p.publish()
}

func (p *PeerPool) publish() {
	p.mu.Lock()
	f := p.flush
	p.mu.Unlock()
	if f != nil {
		f()
	}
}

func (p *PeerPool) emit(code, reason string) {
	p.mu.Lock()
	axis, ev := p.axis, p.ev
	p.mu.Unlock()
	if ev != nil {
		ev("pool", code, axis+":"+reason)
	}
}

func (p *PeerPool) dropPin(reason string, matched func() bool) bool {
	p.mu.Lock()
	hit := matched()
	if hit {
		p.restorePinTookLocked()
		p.pinKey = ""
	}
	p.mu.Unlock()
	if hit {
		p.publish()
		p.emit("pin_dropped", reason)
	}
	return hit
}

func NewPeerPool(addrs []string, rotate time.Duration) *PeerPool {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	p := &PeerPool{addrs: cp, rotate: rotate, now: func() int64 { return time.Now().Unix() }}
	p.health = newHealthSet(&p.now)
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

func (p *PeerPool) fail(reason string) (addr string, moved bool) {
	p.mu.Lock()

	if p.pinnedLocked() {
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	prev := p.cur
	burned := ""
	if p.burnLocked(p.addrs[p.cur]) {
		p.burns.Add(1)
		burned = p.addrs[p.cur]
	}
	p.advanceFailLocked()
	a := p.addrs[p.cur]
	moved = p.cur != prev
	axis, ev := p.axis, p.ev
	p.mu.Unlock()
	if burned != "" && ev != nil {
		ev("burn", reason, axis+":"+burned)
	}
	p.publish()
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
		p.publish()
	}
	return a, moved
}

func (p *PeerPool) nextEndpoint(proactive bool) (addr string, moved bool) {
	if proactive {
		return p.rotateOnce()
	}
	return p.fail("tun-probe")
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
		p.publish()
	}
}

func (p *PeerPool) rejectCandidate(prev string) {
	p.mu.Lock()
	burned := ""
	if bad := p.addrs[p.cur]; bad != prev && p.burnLocked(bad) {
		p.burns.Add(1)
		burned = bad
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
	axis, ev := p.axis, p.ev
	p.mu.Unlock()

	if burned != "" && ev != nil {
		ev("burn", "unbindable", axis+":"+burned)
	}
	p.publish()
}

func (p *PeerPool) clearBurn(addr string) bool {
	p.mu.Lock()
	cleared := p.health.clear(addr)
	axis, ev := p.axis, p.ev
	p.mu.Unlock()
	if cleared {
		if ev != nil {
			ev("heal", "tun-probe", axis+":"+addr)
		}
		p.publish()
	}
	return cleared
}

func (p *PeerPool) restoreAll() {
	p.mu.Lock()
	cleared := p.health.clearAll()
	p.mu.Unlock()
	if cleared {
		p.publish()
	}
}

func (p *PeerPool) retestNow(addr string) bool {
	p.mu.Lock()
	ok := p.health.retestNow(addr)
	p.mu.Unlock()
	if ok {
		p.publish()
	}
	return ok
}

func (p *PeerPool) markSuspect(addr, reason string) {
	if addr == "" {
		return
	}
	p.mu.Lock()
	if p.pinKey == addr {
		p.mu.Unlock()
		return
	}
	fresh := p.health.burn(addr)
	axis, ev := p.axis, p.ev
	p.mu.Unlock()
	if fresh {
		p.burns.Add(1)
		if ev != nil {
			ev("burn", reason, axis+":"+addr)
		}
	}
	p.publish()
}

func (p *PeerPool) selectEntry(key string) bool {
	p.mu.Lock()
	idx := -1
	for i, a := range p.addrs {
		if a == key {
			idx = i
			break
		}
	}
	if idx < 0 {
		p.mu.Unlock()
		return false
	}

	if p.pinKey != key {
		if p.pinKey != "" {
			p.restorePinTookLocked()
		}
		p.pinTook = p.health.rec(key)
		p.health.clear(key)
	}
	p.pinKey = key
	p.pickLocked(idx)
	p.mu.Unlock()
	p.publish()
	return true
}

func (p *PeerPool) pinLandedOn(addr string) {
	p.mu.Lock()
	changed := p.pinnedLocked() && p.pinKey == addr
	if changed {

		p.pinKey, p.pinTook = "", nil
	}
	p.mu.Unlock()
	if changed {
		p.publish()
	}
}

func (p *PeerPool) restorePinTookLocked() {
	if p.pinTook != nil && p.pinKey != "" {
		p.health.recs[p.pinKey] = p.pinTook
	}
	p.pinTook = nil
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

type poolCmd struct {
	Cmd  string `json:"cmd"`
	Low  string `json:"low"`
	High string `json:"high"`
	Kind string `json:"kind"`
	Key  string `json:"key"`

	Epoch int64 `json:"epoch"`
}

func staleVerdict(c poolCmd, epoch int64) bool {
	return (c.Cmd == cmdOK || c.Cmd == cmdFail) && c.Epoch != epoch
}

func claimMailbox(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	taken := path + ".taken"
	if os.Rename(path, taken) != nil {
		return nil, false
	}
	data, err := os.ReadFile(taken)
	os.Remove(taken)
	return data, err == nil
}

func readPoolCmd(path string) (c poolCmd, ok bool) {
	data, ok := claimMailbox(path)
	if !ok || json.Unmarshal(data, &c) != nil || (c.Key == "" && c.Cmd == "") {
		return poolCmd{}, false
	}
	return c, true
}

func readPoolCmds(path string) []poolCmd {
	data, ok := claimMailbox(path)
	if !ok {
		return nil
	}
	var out []poolCmd
	for _, line := range bytes.Split(data, []byte("\n")) {
		var c poolCmd
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &c) != nil {
			continue
		}
		if c.Key == "" && c.Cmd == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

const cmdFail = "fail"

const cmdOK = "ok"

const cmdRetest = "retest"

type pinnable interface {
	isPinned() bool
	releasePin()
}

type lowAxis interface {
	activeIdx() int
	eligibleCount() int
	burnCount() uint64
	restoreAll()
}

type highAxis interface {
	activeIdx() int
}

type poolPair interface {
	live() (low, high string)
	kinds() (lowKind, highKind string)
	keepCursorOn(low, high string)
	clear(kind, key string) bool
	burn(kind, key, reason string)
	pick(kind, key string) bool
	retest(kind, key string) bool
}

type walkPolicy struct {
	mu   sync.Mutex
	od   odometer
	pins []pinnable
	low  lowAxis
	high highAxis

	lowAxisSet atomic.Bool
}

func (w *walkPolicy) pinnedLocked() bool {
	for _, p := range w.pins {
		if p.isPinned() {
			return true
		}
	}
	return false
}

func (w *walkPolicy) hasLow() bool { return w.lowAxisSet.Load() }

func (w *walkPolicy) setLowLocked(low lowAxis) {
	w.low = low
	w.lowAxisSet.Store(low != nil)
}

func (w *walkPolicy) reset() { w.od.restart() }

func (w *walkPolicy) walk(rotLow, rotHigh func(proactive bool)) (stepped, lowBurned bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pinnedLocked() {
		for _, p := range w.pins {
			p.releasePin()
		}
	}
	switch {
	case w.low != nil:

		lap := w.od.failed(w.low.eligibleCount)
		before := w.low.burnCount()

		at := w.low.activeIdx()
		rotLow(false)
		lowBurned = w.low.burnCount() != before
		stepped = w.low.activeIdx() != at
		if w.high != nil && lap {
			hat := w.high.activeIdx()
			rotHigh(false)
			if w.high.activeIdx() != hat {
				w.low.restoreAll()
				stepped = true
			}
		}
		return stepped, lowBurned
	case w.high != nil:
		at := w.high.activeIdx()
		rotHigh(false)
		return w.high.activeIdx() != at, false
	}
	return false, false
}

type rotationController struct {
	walkPolicy
	pair     poolPair
	liveFn   func() (low, high string)
	dst, src *PeerPool
	st       *coreStatus
	verdict  string
	pinbox   string

	measured atomic.Pointer[pairNow]

	accused  atomic.Pointer[pairNow]
	port     portRung
	session  sessionRung
	revive   reviveClock
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

func (c *rotationController) bind(dst, src *PeerPool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dst, c.src = dst, src
	c.pair = peerPair{dst: dst, src: src}
	c.pins, c.high, c.rotate = nil, nil, 0
	c.setLowLocked(nil)
	if dst != nil {
		c.pins = append(c.pins, dst)
		c.setLowLocked(dst)
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

func (c *rotationController) bindEdges(p *wsPool) {
	if p == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pair = edgePair{p}
	c.pins = []pinnable{p}
	c.high = wsSNIs{p}
	c.setLowLocked(nil)
	if p.ipsCount() >= 2 {
		c.setLowLocked(wsEdges{p})
	}
}

type peerPair struct{ dst, src *PeerPool }

func (p peerPair) kinds() (string, string) { return "dst", "src" }

func (p peerPair) live() (low, high string) {
	if p.dst != nil {
		low = p.dst.current()
	}
	if p.src != nil {
		high = p.src.current()
	}
	return low, high
}

func (p peerPair) axis(kind string) *PeerPool {
	if kind == "src" {
		return p.src
	}
	return p.dst
}

func (p peerPair) keepCursorOn(low, high string) {
	p.dst.keepCursorOn(low)
	p.src.keepCursorOn(high)
}

func (p peerPair) clear(kind, key string) bool {
	a := p.axis(kind)
	return a != nil && key != "" && a.clearBurn(key)
}

func (p peerPair) burn(kind, key, reason string) {
	if a := p.axis(kind); a != nil {
		a.markSuspect(key, reason)
	}
}

func (p peerPair) pick(kind, key string) bool {
	a := p.axis(kind)
	return a != nil && key != "" && a.selectEntry(key)
}

func (p peerPair) retest(kind, key string) bool {
	a := p.axis(kind)
	return a != nil && key != "" && a.retestNow(key)
}

func (c *rotationController) active() bool { return c != nil && (c.dst != nil || c.src != nil) }

func (c *rotationController) livePair() (low, high string) {
	if c.liveFn != nil {
		return c.liveFn()
	}
	if c.pair == nil {
		return "", ""
	}
	return c.pair.live()
}

func (c *rotationController) underJudgement() (low, high string) {
	if m := c.measured.Load(); m != nil {
		return m.low, m.high
	}
	return "", ""
}

func (c *rotationController) pairStatus() (low, high, lowKind, highKind string) {
	if c.pair == nil {
		return "", "", "", ""
	}
	lowKind, highKind = c.pair.kinds()
	low, high = c.livePair()
	return low, high, lowKind, highKind
}

func joinStatus(st *coreStatus, p *PeerPool, axis string) {
	if p == nil {
		return
	}
	p.attach(axis, st.event, st.write)
	st.addHealth(p.healthRows)
}

func (c *rotationController) attachStatus(st *coreStatus) {
	c.st = st
	c.verdict, c.pinbox = st.verdictPath(), st.pinPath()
}

func (c *rotationController) polls() bool {
	return c != nil && (c.active() || c.verdict != "" || c.pinbox != "")
}

func (c *rotationController) spendFreeRungs() bool {
	if c.port.try() {
		return false
	}

	c.st.portClaimLost()
	return !c.session.try()
}

func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) (dstBurned bool) {
	if !c.spendFreeRungs() {
		return false
	}
	moved, burned := c.walk(rotDst, rotSrc)

	if moved {
		c.refill()
		c.revive.restart()
		return burned
	}

	if c.revive.try(time.Now()) {
		c.refill()
		c.st.event("down", "ladder-revive", "")
	}
	return burned
}

func (c *rotationController) refill() {
	c.port.restart()
	c.session.restart()
}

func (c *rotationController) restart() {
	c.reset()
	c.refill()
}

func (c *rotationController) success() {
	c.accused.Store(nil)
	c.revive.restart()
	c.restart()
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

func (c *rotationController) poll(rotLow, rotHigh func(proactive bool), applied func(kind, key string),
	pathEpoch func() int64) (moved bool) {
	if cmd, ok := readPoolCmd(c.verdict); ok {
		moved = c.judge(cmd, rotLow, rotHigh, pathEpoch())
	}

	cmds := readPoolCmds(c.pinbox)
	if c.pair == nil {
		return moved
	}
	for _, cmd := range cmds {
		if cmd.Key == "" {
			continue
		}
		switch cmd.Cmd {
		case cmdRetest:
			if c.pair.retest(cmd.Kind, cmd.Key) {
				log.Printf("core: %s %s may be tried again now (operator)", cmd.Kind, cmd.Key)
			}
		default:
			if c.pair.pick(cmd.Kind, cmd.Key) {
				log.Printf("core: pin %s %s (operator)", cmd.Kind, cmd.Key)
				if applied != nil {
					applied(cmd.Kind, cmd.Key)
				}
				moved = true
			}
		}
	}
	return moved
}

func (c *rotationController) judge(cmd poolCmd, rotLow, rotHigh func(proactive bool),
	epoch int64) (moved bool) {
	switch {
	case staleVerdict(cmd, epoch):

		log.Printf("core: dropping a tun-probe verdict for path epoch %d — the carrier is on %d now",
			cmd.Epoch, epoch)
	case cmd.Cmd == cmdOK:

		c.success()

		c.st.carrying()
		if c.pair == nil {
			return false
		}
		lowKind, highKind := c.pair.kinds()
		c.pair.clear(lowKind, cmd.Low)
		c.pair.clear(highKind, cmd.High)
	case cmd.Cmd == cmdFail:

		if c.pair == nil {
			c.fail(rotLow, rotHigh)
			return false
		}

		if cmd.Low == "" && cmd.High == "" {
			c.spendFreeRungs()
			return false
		}
		lowKind, highKind := c.pair.kinds()
		liveLow, liveHigh := c.livePair()
		lowGone := cmd.Low != "" && cmd.Low != liveLow
		highGone := cmd.High != "" && cmd.High != liveHigh
		if lowGone || highGone {

			kind, key := lowKind, cmd.Low
			if highGone && (!lowGone || !c.hasLow()) {
				kind, key = highKind, cmd.High
			}
			log.Printf("core: %s · %s failed by the node's tun probe, but the pool has since moved to "+
				"%s · %s — burning what was measured, staying put", cmd.Low, cmd.High, liveLow, liveHigh)
			c.pair.burn(kind, key, "tun-probe")
			return false
		}

		switch a := c.accused.Load(); {
		case a == nil:
			c.accused.Store(&pairNow{low: liveLow, high: liveHigh})
		case a.low != liveLow || a.high != liveHigh:
			log.Printf("core: the tunnel came back on %s · %s while the ladder was climbing for "+
				"%s · %s — starting over rather than charging this one", liveLow, liveHigh, a.low, a.high)
			c.restart()
			c.accused.Store(&pairNow{low: liveLow, high: liveHigh})
			return false
		}

		c.pair.keepCursorOn(liveLow, liveHigh)
		c.measured.Store(&pairNow{low: liveLow, high: liveHigh})
		burned := c.fail(rotLow, rotHigh)
		c.measured.Store(nil)

		nowLow, nowHigh := c.pair.live()
		moved = burned || nowLow != liveLow || nowHigh != liveHigh
		if moved {

			log.Printf("core: %s · %s failed by the node's tun probe — the ladder walked off it",
				cmd.Low, cmd.High)
		}
	}
	return moved
}

func (p *PeerPool) healthRows() []healthStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	rows := make([]healthStatus, 0, len(p.addrs))
	for _, a := range p.addrs {
		hs := healthStatus{Key: a, Kind: p.axis, State: "healthy", Pin: a == p.pinKey}
		if r := p.health.rec(a); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		rows = append(rows, hs)
	}
	return rows
}
