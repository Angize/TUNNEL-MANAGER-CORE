package packet

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

type PeerPool struct {
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
	p.health.markTried(p.chosen)
	return p.chosen
}

func (p *PeerPool) pickLocked(idx int) string {
	p.cur = idx
	p.chosen = ""
	p.health.markTried(p.addrs[idx])
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

func (p *PeerPool) burnLocked(addr string) {
	p.health.burn(addr)
}

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
	p.commitLocked(p.bestIdxLocked(p.cur))
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
	p.burnLocked(p.addrs[p.cur])
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
	for idx, a := range p.addrs {
		if a == prev {
			p.commitLocked(idx)
			break
		}
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
	p.mu.Lock()
	released := false
	if p.pinKey != "" && p.pinKey == addr {
		if p.pinTries++; p.pinTries >= pinFailRelease {
			p.restorePinTookLocked()
			p.pinKey, p.pinTries = "", 0
			released = true
		}
	}
	p.mu.Unlock()
	if released {
		p.writeStatus()
	}
}

func (p *PeerPool) pinCannotLand(key string) bool {
	p.mu.Lock()
	cleared := p.pinnedLocked() && p.pinKey == key
	if cleared {
		p.restorePinTookLocked()
		p.pinKey = ""
	}
	p.mu.Unlock()
	if cleared {
		p.writeStatus()
	}
	return cleared
}

func (p *PeerPool) releasePin() {
	p.mu.Lock()
	changed := p.pinKey != ""
	if changed {
		p.restorePinTookLocked()
		p.pinKey = ""
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
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

type rotationController struct {
	mu       sync.Mutex
	dst, src *PeerPool
	verdict  string
	port     portRung
	session  sessionRung
	od       odometer
	pinFails int
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

func (c *rotationController) active() bool { return c != nil && (c.dst != nil || c.src != nil) }

func (c *rotationController) setVerdict(path string) { c.verdict = path }

func (c *rotationController) polls() bool {
	return c != nil && (c.active() || c.verdict != "" || c.port.armed())
}

func (c *rotationController) pinned() bool {
	return (c.dst != nil && c.dst.isPinned()) || (c.src != nil && c.src.isPinned())
}

func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) (condemned bool) {

	if c.port.try() {
		return false
	}

	if c.session.try() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pinned() {

		c.pinFails++
		if c.pinFails < pinFailRelease {
			return false
		}
		c.pinFails = 0
		if c.dst != nil {
			c.dst.releasePin()
		}
		if c.src != nil {
			c.src.releasePin()
		}

	} else {
		c.pinFails = 0
	}
	if c.dst != nil {

		lap := c.od.failed(c.dst.eligibleCount)
		rotDst(false)
		if c.src != nil && lap {
			rotSrc(false)
		}
		return true
	}
	if c.src != nil {
		rotSrc(false)
		return true
	}
	return false
}

func (c *rotationController) success() {

	c.mu.Lock()
	defer c.mu.Unlock()
	c.od.restart()
	c.pinFails = 0
}

func (c *rotationController) proactive(rotDst, rotSrc func(proactive bool), now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rotate <= 0 || c.rotateAt.IsZero() || !now.After(c.rotateAt) {
		return
	}
	if c.pinned() {
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
	judged := false
	if cmd, ok := readPoolCmd(c.verdict); ok {
		c.judge(cmd, rotDst, rotSrc, ev, pathEpoch())
		judged = true
	}

	c.port.tick(time.Now(), judged)
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

		c.port.restart()
		c.session.restart()

		if c.dst != nil && cmd.Key != "" && c.dst.clearBurn(cmd.Key) && ev != nil {
			ev("heal", "peer-retest", cmd.Key)
		}
		if c.src != nil && cmd.Src != "" && c.src.clearBurn(cmd.Src) && ev != nil {
			ev("heal", "src-retest", cmd.Src)
		}
	case cmd.Cmd == cmdFail:

		condemned := c.fail(rotDst, rotSrc)

		if condemned && c.dst != nil {
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
