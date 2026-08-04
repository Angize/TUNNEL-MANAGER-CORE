package packet

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// PeerPool rotates a client's DESTINATION endpoint (or, as a second instance, its SOURCE IP) across a
// list of candidates, so one blocked IP does not kill the tunnel. It shares the ws edge pool's health
// primitives (ws_pool.go) — the same healthy → suspect → dead FSM — and, for a destination pool, the
// same out-of-band retest: dueRetests hands a burned endpoint to the carrier's prober (peer_probe.go)
// and retestResult walks the FSM on the answer — EXCEPT for an endpoint the node's tun probe condemned,
// which only the node takes back. See condemned. A source pool has no prober at all; see succeeded.
type PeerPool struct {
	mu         sync.Mutex
	writeMu    sync.Mutex            // serializes the status file write+rename so concurrent writers don't race the shared .tmp
	addrs      []string              // candidate endpoints ("ip" or "ip:port"), in operator order
	health     map[string]*healthRec // absent == healthy; only suspect/dead entries are tracked
	cur        int                   // index of the active endpoint
	autoBurn   bool                  // burn a failing endpoint (vs. only rotate past it)
	rotate     time.Duration         // proactive rotation interval (0 = failover-only)
	statusPath string                // status file the panel reads (empty = off; also gates the pin cmd file)
	// pinKey/pinUntil back the panel's "make this active" button — a MOMENTARY jump, NOT a lock. The pin
	// RELEASES the instant the carrier lands on it (about one handshake); pinUntil is only a CEILING for a
	// pick that never connects, so a dead choice cannot strand the tunnel for the whole TTL.
	pinKey   string // operator "make active" endpoint; current() forces it until it lands OR pinUntil lapses
	pinUntil int64  // unix-secs ceiling for a NOT-YET-LANDED pin only; a landed pin releases well before this
	// chosen is the endpoint an ADVANCE deliberately moved onto, which currentLocked returns instead of
	// re-selecting: the two follow different rules on purpose, and a reader must not overrule the rotation.
	// Maintained only by commitLocked/pickLocked, so it can never point somewhere cur is not.
	chosen string
	now    func() int64 // injectable clock (unix seconds); overridden in tests
}

// NewPeerPool builds a pool from the candidate endpoints. addrs must be non-empty (the caller only
// builds a pool when rotation is on with >1 endpoint; a 1-endpoint pool is harmless — it never
// rotates). rotate is the proactive interval; autoBurn drops a failing endpoint from rotation.
func NewPeerPool(addrs []string, autoBurn bool, rotate time.Duration, statusPath string) *PeerPool {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	p := &PeerPool{addrs: cp, health: map[string]*healthRec{}, autoBurn: autoBurn, rotate: rotate,
		statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.writeStatus() // publish the initial state so the panel sees the pool immediately
	return p
}

// current returns the active endpoint (never empty for a non-empty pool). It prefers a fully-HEALTHY
// endpoint (scanning forward from cur for variety), then a DUE burned one (its backoff elapsed — the
// live data plane retries it), then the least-bad. A fresh pin forces the pinned endpoint. current()
// commits cur to what it returns, so a subsequent fail() burns the endpoint that was actually used.
func (p *PeerPool) current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked()
}

// commitLocked moves cur to idx as a DELIBERATE choice — an advance, or a rejected candidate being
// undone — so currentLocked hands that endpoint back instead of re-selecting (see the chosen field).
// pickLocked is the same move WITHOUT the commit, for currentLocked's own passes and for a pin. Every
// write to p.cur goes through one of the two, so chosen can never go stale.
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
		if p.now() < p.pinUntil {
			for idx, a := range p.addrs {
				if a == p.pinKey {
					return p.pickLocked(idx)
				}
			}
			p.pinKey, p.pinUntil = "", 0 // pinned endpoint was removed from the pool -> forget it
		} else {
			p.pinKey, p.pinUntil = "", 0 // expired -> resume normal rotation
		}
	}
	n := len(p.addrs)
	now := p.now()
	// Pass 0: the endpoint an advance deliberately chose. The passes below re-select under DIFFERENT rules,
	// so without this a reader walks straight back off the rotation's choice — a failover lands on a DUE
	// burned endpoint that pass 1 refuses while anything healthy exists, and steps OFF what it just burned
	// where pass 3 does not. udp/raw/flux use nextEndpoint's address; tcp re-asks current().
	if p.chosen != "" && p.addrs[p.cur] == p.chosen {
		return p.chosen
	}
	// Pass 1: a fully-healthy endpoint, scanning forward from cur (consecutive picks vary).
	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if p.health[p.addrs[idx]] == nil {
			return p.pickLocked(idx)
		}
	}
	// Pass 2: none healthy — a DUE burned endpoint (its retest time arrived) gets a live retry.
	for k := 0; k < n; k++ {
		idx := (p.cur + k) % n
		if r := p.health[p.addrs[idx]]; r != nil && r.nextRetest <= now {
			return p.pickLocked(idx)
		}
	}
	// Pass 3: nothing healthy or due — the least-bad endpoint (never dead-end).
	return p.pickLocked(p.bestIdxLocked(-1))
}

// size is the number of endpoints in the pool. It is fixed at construction, so no lock is needed.
func (p *PeerPool) size() int { return len(p.addrs) }

// all returns every endpoint the pool was built with, burned or not. addrs is fixed at construction
// (burning only marks health), so the list is stable for the pool's lifetime.
func (p *PeerPool) all() []string {
	out := make([]string, len(p.addrs))
	copy(out, p.addrs)
	return out
}

// tierLocked ranks an endpoint for the least-bad fallback: 0 healthy, 1 suspect, 2 dead, with its
// nextRetest as the tiebreak within a tier. Caller holds the lock.
func (p *PeerPool) tierLocked(addr string) (tier int, next int64) {
	r := p.health[addr]
	if r == nil {
		return 0, 0
	}
	if r.state == stateDead {
		return 2, r.nextRetest
	}
	return 1, r.nextRetest
}

// bestIdxLocked returns the index of the least-bad endpoint (healthy < suspect < dead, soonest
// nextRetest breaking ties), optionally excluding one index (so fail() always MOVES off the endpoint
// it just burned). Caller holds the lock; addrs is non-empty.
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
	if best == -1 { // every candidate was excluded (single-endpoint pool) — stay put
		return except
	}
	return best
}

// burnLocked moves the endpoint's health FSM on a failure: healthy → suspect, or one step further down
// the backoff toward dead if it is already tracked. Caller holds the lock. It does NOT consult auto-burn
// itself — the callers do, and differently: fail() is about a REMOTE endpoint that looks unreachable,
// which is what auto-burn is a policy for; failUnusable/rejectCandidate are about a LOCAL impossibility.
func (p *PeerPool) burnLocked(addr string) {
	r := p.health[addr]
	if r == nil {
		p.health[addr] = &healthRec{state: stateSuspect, nextRetest: p.now() + suspectBackoff[0]}
		return
	}
	p.failRetestLocked(r)
}

// retestBackoff walks a failing endpoint's suspect->dead backoff FSM: healthy/suspect steps down the
// backoff schedule, dead resets to the slow retest. Shared verbatim by PeerPool and wsPool.
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

// failRetestLocked reschedules a tracked endpoint after a failed (re)try: a suspect walks the backoff
// list; running off its end drops it to dead; a dead endpoint stays dead on the slow interval. Same
// schedule the ws edge pool uses. Caller holds the lock.
func (p *PeerPool) failRetestLocked(r *healthRec) {
	retestBackoff(r, p.now())
}

// advanceFailLocked moves cur OFF the just-failed endpoint to the best next one to try: a healthy
// endpoint if any, else a due burned one, else the least-bad OTHER endpoint (never re-sticks on the
// endpoint we just burned). Caller holds the lock; addrs has >=2 entries.
func (p *PeerPool) advanceFailLocked() {
	n := len(p.addrs)
	now := p.now()
	for k := 1; k <= n; k++ { // healthy, starting past cur so we move off it
		idx := (p.cur + k) % n
		if p.health[p.addrs[idx]] == nil {
			p.commitLocked(idx)
			return
		}
	}
	for k := 1; k <= n; k++ { // else a due burned endpoint
		idx := (p.cur + k) % n
		if r := p.health[p.addrs[idx]]; r != nil && r.nextRetest <= now {
			p.commitLocked(idx)
			return
		}
	}
	p.commitLocked(p.bestIdxLocked(p.cur)) // else least-bad among the others
}

// advanceEligibleLocked moves cur to another HEALTHY endpoint for a proactive rotate, returning whether
// it moved. A burned endpoint is not eligible, not even one whose retest is due: re-admission belongs to
// whatever burned it, and jumping the live tunnel onto an endpoint that has proven nothing, to find out,
// is the very thing this replaced. With nothing healthy elsewhere it stays put, so the proactive timer
// never tears a working connection down for nothing. Caller holds the lock; addrs has >=2 entries.
func (p *PeerPool) advanceEligibleLocked() bool {
	n := len(p.addrs)
	for k := 1; k <= n; k++ {
		idx := (p.cur + k) % n
		if idx == p.cur {
			break
		}
		if p.health[p.addrs[idx]] == nil {
			p.commitLocked(idx)
			return true
		}
	}
	return false
}

// markNodeBurn records that the burn now on addr was decided by the NODE's tun probe — the one
// measurement that watches what actually CROSSES the tunnel. Called right after the burn, with the same
// address the burn event named, so the mark and the log can never disagree. A no-op when auto-burn left
// no record to mark.
func (p *PeerPool) markNodeBurn(addr string) {
	p.mu.Lock()
	if r := p.health[addr]; r != nil {
		r.nodeBurn = true
	}
	p.mu.Unlock()
}

// condemned reports that the node's tun probe burned this endpoint and has not taken it back. Such an
// endpoint is not probed, not healed by a live success, and not eligible for rotation. It returns ONLY
// through probeAllNow — which the node fires itself once it has walked the whole pool and the tunnel is
// STILL dead, and which the panel offers as "probe now" — or through an operator pin.
//
// The rule is "whatever condemned it is what forgives it", and it is measured, not theoretical: an
// endpoint can answer a real PSK handshake while carrying nothing. On the fleet, 5.75.197.201 answered
// within a second of every rotation onto it and the node's probe then found 20 of 20 packets lost,
// twice. Letting the handshake re-admit it put the tunnel back on a dead IP every three minutes, for
// good. Caller holds the lock.
func condemned(r *healthRec) bool { return r != nil && r.nodeBurn }

// fail reports that the active endpoint looks dead. With auto-burn it is walked down the health FSM
// (healthy→suspect→…→dead); either way the pool advances to the next endpoint to try and returns it
// (plus whether it actually moved).
func (p *PeerPool) fail() (addr string, moved bool) { return p.failWith(false) }

// failUnusable is fail() for a source the KERNEL refuses — an IP not configured on this host — rather
// than a peer that merely looks unreachable, so it burns even with auto-burn OFF. Auto-burn is a policy
// about REMOTE reachability, where a peer that times out now may answer in a minute; an address this box
// cannot send from is a local fact no policy changes, and leaving it healthy makes rotation return to it.
func (p *PeerPool) failUnusable() (addr string, moved bool) { return p.failWith(true) }

func (p *PeerPool) failWith(unusable bool) (addr string, moved bool) {
	p.mu.Lock()
	// A live operator pin freezes failover ATOMICALLY — checked under the same p.mu that selectEntry
	// takes — so an in-flight fail() racing a just-set pin can't burn or advance off the pinned endpoint
	// (current() forces it until it lands or its TTL lapses). This is the authoritative guard; the
	// rotationController's pinned() check is only a fast path.
	if len(p.addrs) < 2 || p.pinnedLocked() { // nothing to rotate to, or a pin holds it
		a := p.addrs[p.cur]
		p.mu.Unlock()
		return a, false
	}
	prev := p.cur
	if p.autoBurn || unusable {
		p.burnLocked(p.addrs[p.cur])
	}
	p.advanceFailLocked()
	a := p.addrs[p.cur]
	moved = p.cur != prev
	p.mu.Unlock()
	p.writeStatus()
	return a, moved
}

// rotateOnce advances to another ELIGIBLE endpoint WITHOUT burning (the proactive-timer path). Returns
// the new endpoint and whether it moved (a 1-endpoint pool, or one where every alternative is burned and
// not yet due, does not move).
func (p *PeerPool) rotateOnce() (addr string, moved bool) {
	p.mu.Lock()
	if len(p.addrs) < 2 || p.pinnedLocked() { // a pin freezes proactive rotation too (atomic under p.mu)
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

// nextEndpoint picks the endpoint a carrier should jump to now: a proactive timed rotate (rotateOnce,
// no burn) or a failover burn+advance (fail). Both return (addr, moved) with identical meaning, so the
// four direct carriers share this one dispatch instead of each open-coding the proactive branch.
func (p *PeerPool) nextEndpoint(proactive bool) (addr string, moved bool) {
	if proactive {
		return p.rotateOnce()
	}
	return p.fail()
}

// keepCursorOn puts cur back on addr — the endpoint the carrier is REALLY using — after a rotation that
// did not take. It exists for make-before-break: when a warm build fails the live connection stays put,
// while fail() has already advanced cur and would publish Active as an endpoint the tunnel was never on.
// The burn fail() recorded is kept; only the cursor goes back. Nil-safe (a source-only rotation beat).
func (p *PeerPool) keepCursorOn(addr string) {
	if p == nil || addr == "" {
		return
	}
	p.mu.Lock()
	moved := false
	if p.addrs[p.cur] != addr {
		for idx, a := range p.addrs {
			if a == addr {
				p.commitLocked(idx) // a DELIBERATE choice: staying put is the outcome of the failed attempt
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

// rejectCandidate UNDOES a rotation whose target the carrier could not actually adopt — the udp source
// rebind failed because the new source IP is not on this host. nextEndpoint has already advanced cur onto
// it (and, on a failover, burned prev), but the socket never left prev: so burn the unbindable candidate
// and restore cur to prev, clearing any burn the failover put on it. It never burns prev.
func (p *PeerPool) rejectCandidate(prev string) {
	p.mu.Lock()
	if bad := p.addrs[p.cur]; bad != prev {
		p.burnLocked(bad) // the candidate can't bind on this host — pull it from rotation
	}
	for idx, a := range p.addrs {
		if a == prev {
			delete(p.health, prev) // prev is the live source: undo the failover burn / any stale mark
			p.commitLocked(idx)    // the socket never left prev, so prev IS the deliberate endpoint
			break
		}
	}
	p.mu.Unlock()
	p.writeStatus()
}

// healEvents emits the paired heal events after a datagram carrier's endpoints prove alive again:
// rc.success() clears any transient burn and returns the recovered destination/source IPs ("" when
// nothing healed), which become "peer-retest"/"src-retest". Shared by udp/raw/flux; st.event is nil-safe.
func healEvents(st *coreStatus, rc *rotationController) {
	dh, sh := rc.success()
	if dh != "" {
		st.event("heal", "peer-retest", dh)
	}
	if sh != "" {
		st.event("heal", "src-retest", sh)
	}
}

// succeeded clears any health record on the CURRENT endpoint — a live success proves it healthy right
// now, so a transient block heals. Returns the recovered address when it actually cleared a burn (a heal
// transition), else "", so the carrier can emit a discrete heal event. Writes the status file only then.
//
// It will NOT touch a burn the node's tun probe decided. A frame coming back says an endpoint answered
// US; the node measured what CROSSES and found nothing, twice — and one reply a second after a rotation
// used to wipe exactly that. See condemned. What is left here is every OTHER burn: the SOURCE pool's,
// where a returning frame really is the whole answer (it proves this host can send from the address its
// socket is bound to, and nothing else can probe a source), and a tcp carrier's own dial-failure burn,
// which a connection that came up on the same endpoint answers like for like.
func (p *PeerPool) succeeded() string {
	p.mu.Lock()
	a := p.addrs[p.cur]
	r := p.health[a]
	changed := r != nil && !condemned(r)
	if changed {
		delete(p.health, a)
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
		return a
	}
	return ""
}

// dueRetests returns the burned endpoints whose backoff has elapsed — the ones the carrier's
// out-of-band prober should test now. Two kinds are left out. The ACTIVE endpoint, because it is the one
// the live carrier is on, its verdict belongs to the node's tun probe, and an answer from it cannot be
// told apart from the traffic already crossing it. And any endpoint the node CONDEMNED, because a
// handshake it answers is not the measurement that condemned it — see condemned. Leaving those alone
// also stops us poking an IP a censor is already watching.
func (p *PeerPool) dueRetests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var out []string
	for i, a := range p.addrs {
		if i == p.cur {
			continue
		}
		if r := p.health[a]; r != nil && r.nextRetest <= now && !condemned(r) {
			out = append(out, a)
		}
	}
	return out
}

// retestResult feeds one out-of-band probe verdict into the endpoint's FSM: a peer that answered a real
// handshake is re-admitted to rotation, one that did not walks the backoff a step further toward dead.
// Returns true only on the heal transition, so the carrier emits exactly one event per recovery.
func (p *PeerPool) retestResult(addr string, alive bool) bool {
	p.mu.Lock()
	r := p.health[addr]
	if r == nil { // cleared from under us (an operator pin / "probe now") — nothing to record
		p.mu.Unlock()
		return false
	}
	if alive {
		delete(p.health, addr)
	} else {
		p.failRetestLocked(r)
	}
	p.mu.Unlock()
	p.writeStatus()
	return alive
}

// probeAllNow pulls EVERY suspect/dead endpoint's retest forward to now AND takes back the node's
// condemnations, so the prober tests them all on its next tick instead of waiting out the backoff — a
// lifted block heals at once. This is the ONLY way a node-burned endpoint comes back, and it is the
// right one: whoever reaches for this control is saying the problem was never these IPs. The node fires
// it itself once it has walked the whole destination x source matrix and the tunnel is STILL dead; the
// panel offers it as "probe now" (delivered as a signal, which carries no key — hence all of them).
func (p *PeerPool) probeAllNow() {
	p.mu.Lock()
	now := p.now()
	for _, r := range p.health {
		r.nextRetest = now
		r.nodeBurn = false
	}
	p.mu.Unlock()
	p.writeStatus()
}

// selectEntry PINS a specific endpoint as the active one: current() forces it until the carrier lands on
// it (pinApplied clears the pin) or pinTTL elapses with no land. So it is "jump exactly here and keep
// trying until connected" — it survives a transient outage but self-releases on success and cannot
// strand the tunnel on a dead endpoint. It also clears any suspect/dead mark. False if key is unknown.
func (p *PeerPool) selectEntry(key string) bool {
	p.mu.Lock()
	ok := false
	for idx, a := range p.addrs {
		if a == key {
			p.pinKey = key
			p.pinUntil = p.now() + pinTTL
			delete(p.health, key) // the operator picked this one deliberately: burn and condemnation both
			p.pickLocked(idx)     // the pin key governs while it is live; normal selection resumes once it lapses
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

// pinLandedOn releases a live manual pin ONLY when the carrier really came up on the pinned endpoint.
// tcp needs the comparison because dialLoop can adopt a carrier the rotation timer PRE-BUILT, whose
// endpoint was resolved before the pin existed — releasing then reports the operator's jump as complete
// while the tunnel sits somewhere else, and resumes rotation as if the pick had been honoured.
func (p *PeerPool) pinLandedOn(addr string) {
	p.mu.Lock()
	changed := p.pinnedLocked() && p.pinKey == addr
	if changed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// pinCannotLand is pinLandedOn's opposite: the jump's endpoint turned out to be unusable outright — a
// source IP not configured on this host, which no number of retries can fix — so it clears the pin and
// the pool moves on at once. pinTTL is a ceiling for a pick that MIGHT still connect; once "cannot be
// used at all" is settled there is nothing to wait for. Keyed, so it never cancels a re-aimed jump.
func (p *PeerPool) pinCannotLand(key string) bool {
	p.mu.Lock()
	cleared := p.pinnedLocked() && p.pinKey == key
	if cleared {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if cleared {
		p.writeStatus()
	}
	return cleared
}

// releasePin drops a manual pin whose endpoint has been PROVEN blocked (repeated failovers that never
// landed), so current() stops forcing the dead endpoint for the rest of pinTTL and the tunnel recovers
// on a live one at once. A transient outage heals before the fail threshold and never reaches here.
func (p *PeerPool) releasePin() {
	p.mu.Lock()
	changed := p.pinKey != ""
	if changed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// expirePinIfLapsed clears — and flushes to the status file — a pin whose TTL has just lapsed with no
// landing. current() also drops a lapsed pin, but it runs under the hot lock and cannot write the status
// file, so without this the panel keeps showing a pin the dataplane no longer honours until the next
// unrelated status write. Writes ONLY on the expiry transition, so it is a no-op on the steady 1s tick.
func (p *PeerPool) expirePinIfLapsed() {
	p.mu.Lock()
	lapsed := p.pinKey != "" && p.now() >= p.pinUntil
	if lapsed {
		p.pinKey, p.pinUntil = "", 0
	}
	p.mu.Unlock()
	if lapsed {
		p.writeStatus()
	}
}

// pinnedLocked reports whether a manual pin is still in its force window. Caller holds p.mu.
func (p *PeerPool) pinnedLocked() bool { return p.pinKey != "" && p.now() < p.pinUntil }

// isPinned reports whether a manual pin is still in its force window, during which failover and
// proactive rotation are held off so the jump lands exactly. After the window it returns false and
// normal rotation resumes.
func (p *PeerPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinnedLocked()
}

// cmdPath is the sidecar file the node writes a "select endpoint" request into (JSON {key}). Empty when
// the pool has no status path (nothing to poll).
func (p *PeerPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

// poolCmd is one request from the node, read out of the sidecar file. Exactly one field is meaningful
// per command: Key pins that endpoint (the panel's per-IP button), Cmd names an action.
type poolCmd struct {
	Key string `json:"key"`
	Cmd string `json:"cmd"`
}

// cmdFail is the node asking us to treat the current endpoint as dead: burn it and advance, the same
// move a peer that stopped answering triggers here. The node sends it when its own probe finds nothing
// crossing the TUN, which is a signal this side cannot see — our carrier only knows whether frames it
// can authenticate arrive, and on a crypto tunnel that takes the stale window plus a full run of failed
// handshakes to conclude. The FSM stays owned here: the node asks, this file decides what it means.
const cmdFail = "fail"

// readCmd consumes a pending command (written by the node) and returns it. ok=false when none is
// pending or it carries neither field. The file is removed once read, so a command fires exactly once.
func (p *PeerPool) readCmd() (c poolCmd, ok bool) {
	cp := p.cmdPath()
	if cp == "" {
		return c, false
	}
	data, err := os.ReadFile(cp)
	if err != nil {
		return c, false
	}
	os.Remove(cp)
	if json.Unmarshal(data, &c) != nil || (c.Key == "" && c.Cmd == "") {
		return poolCmd{}, false
	}
	return c, true
}

// rotationController couples a client carrier's DESTINATION pool with an optional SOURCE pool and
// centralizes the failover/proactive policy, so every carrier drives rotation identically — it decides
// WHEN, the carrier's own funcs do the swapping. Policy: burn and advance the destination on a dead
// peer, walk the SOURCE once every destination has been tried against it, and freeze both under a pin.
type rotationController struct {
	dst, src *PeerPool
	destRot  int
	pinFails int // consecutive proven-dead rounds while a pin is in force -> auto-release at pinFailRelease
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

// pinned reports whether either pool currently holds an operator pin (rotation is frozen).
func (c *rotationController) pinned() bool {
	return (c.dst != nil && c.dst.isPinned()) || (c.src != nil && c.src.isPinned())
}

// fail is called when the current peer looks dead. rotDst/rotSrc are the carrier's swap funcs. While an
// operator pin is in force it holds off failover until pinFailRelease proven-dead rounds auto-release it.
func (c *rotationController) fail(rotDst, rotSrc func(proactive bool)) {
	if c.pinned() {
		// A pinned endpoint proven blocked auto-releases so the tunnel recovers NOW instead of freezing on it
		// for the rest of pinTTL. Each call here is already a proven-dead round, so a transient blip never
		// reaches even one; only after pinFailRelease decisive rounds does the pin drop and failover resume.
		c.pinFails++
		if c.pinFails < pinFailRelease {
			return
		}
		c.pinFails = 0
		if c.dst != nil {
			c.dst.releasePin()
		}
		if c.src != nil {
			c.src.releasePin()
		}
		// pins cleared — fall through and burn+advance off the blocked endpoint this round
	} else {
		c.pinFails = 0 // not pinned -> reset so a later pin starts its release count fresh
	}
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

// success marks both pools good after the carrier handshakes, resets the dest-cycle counter, and returns
// the dst/src addresses that RECOVERED from a burn this call (empty when nothing healed) so the carrier
// can surface a discrete heal event.
func (c *rotationController) success() (dstHealed, srcHealed string) {
	c.destRot = 0
	c.pinFails = 0 // a live success (the pin landed, or the endpoint healed) resets the release count
	if c.dst != nil {
		dstHealed = c.dst.succeeded()
		// No pinLanded() here either. This runs behind a gate that needs a prior failure, which a jump
		// that simply worked never produces — so a landed pin sat out its whole TTL. The carriers
		// release it themselves, on the endpoint they are PROVEN up on; see the clientLoops.
	}
	if c.src != nil {
		srcHealed = c.src.succeeded()
		// No pinLanded() for the source. A handshake says nothing about whether the SOURCE pin landed:
		// the source swap keeps the session, so this call would release the operator's jump on the
		// strength of an unrelated destination connect. adoptSource* reports the real landing.
	}
	return
}

// proactive fires the timed rotation of BOTH pools when due (a signal-free moving target on each side).
// Held off while a pin is in force so the manual switch is not overridden.
func (c *rotationController) proactive(rotDst, rotSrc func(proactive bool), now time.Time) {
	if c.rotate <= 0 || c.rotateAt.IsZero() || !now.After(c.rotateAt) {
		return
	}
	if c.pinned() {
		c.rotateAt = now.Add(c.rotate) // keep the schedule ticking; just skip this beat
		return
	}
	if c.dst != nil {
		rotDst(true)
	}
	if c.src != nil {
		rotSrc(true)
	}
	c.destRot = 0 // a timed source move restarts the dest cycle (the "all dests tried" count is per-source)
	c.rotateAt = now.Add(c.rotate)
}

// pollPins reads a pending pin command for each pool and, when one is present, pins the requested
// endpoint and calls the carrier's apply func (which re-points the live dataplane at the newly-pinned
// endpoint via the pool's current()). Carriers run this on a ~1s ticker so a manual switch is prompt.
func (c *rotationController) pollPins(applyDst, applySrc func(), rotDst, rotSrc func(proactive bool),
	ev func(kind, code, detail string)) {
	if c.dst != nil {
		if cmd, ok := c.dst.readCmd(); ok {
			switch {
			case cmd.Cmd == cmdFail:
				// Straight into the dead-peer path, so a node-driven failover and a carrier-driven one
				// are the same move: same burn, same advance, same pin handling. Only the trigger differs.
				// The carrier's own rotate publishes "peer-rotate" either way, which cannot say WHO decided
				// -- so mark it here, before the burn, while we still know which endpoint is about to go.
				addr := c.dst.current()
				log.Printf("core: destination %s failed by the node's tun probe — burning and advancing", addr)
				if ev != nil {
					ev("burn", "tun-probe", "ip:"+addr)
				}
				c.fail(rotDst, rotSrc)
				c.dst.markNodeBurn(addr) // the tun probe condemned it; only the tun probe takes it back
			case cmd.Key != "" && c.dst.selectEntry(cmd.Key):
				applyDst()
			}
		}
		c.dst.expirePinIfLapsed() // flush the status file the moment a lapsed pin stops being honoured
	}
	if c.src != nil {
		// The source pool takes pins only. A tun probe cannot tell a bad SOURCE from a bad DESTINATION,
		// and the controller already walks the source once every destination has been tried against it.
		if cmd, ok := c.src.readCmd(); ok && cmd.Key != "" && c.src.selectEntry(cmd.Key) {
			applySrc()
		}
		c.src.expirePinIfLapsed()
	}
}

// peerPoolStatus is the pool state written to the status file the node/panel read. Health carries the
// full per-endpoint FSM (state/fails/next_retest), which is what every reader uses; Pin is the
// operator-pinned endpoint (empty = none).
type peerPoolStatus struct {
	Active  string         `json:"active"`
	Addrs   []string       `json:"addrs"`
	Health  []healthStatus `json:"health"`
	Pin     string         `json:"pin"`
	Updated int64          `json:"updated_unix"`
}

// writeStatus snapshots the pool's live state to statusPath (best effort) so the panel can show which
// endpoint is active, which are burned (and how — suspect vs dead, with the retest countdown), and any
// pin, and can drive the pool via the cmd file. A write error is non-fatal (the dataplane keeps running).
func (p *PeerPool) writeStatus() {
	if p.statusPath == "" {
		return
	}
	// Hold writeMu across BOTH the snapshot and the file write, so concurrent writers can't snapshot in
	// one order and win the write in the other — an older snapshot must never overwrite a newer file
	// (writes are change-driven; there is no periodic re-write to self-correct a stale one). p.mu is
	// always released before any caller reaches writeStatus, so writeMu→p.mu never inverts a lock order.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	health := make([]healthStatus, 0, len(p.addrs))
	for _, a := range p.addrs {
		hs := healthStatus{Key: a, Kind: "ip", State: "healthy"}
		if r := p.health[a]; r != nil {
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
