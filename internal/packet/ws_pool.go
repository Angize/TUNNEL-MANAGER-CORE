// Edge pool for the ws client: a moving-target rotation over separate clean IP and SNI lists. The core
// cycles (edge-IP × SNI) combinations so no single IP or domain stays exposed long enough to be
// fingerprinted, and tracks per-entry HEALTH with a three-state FSM (healthy → suspect → dead) instead
// of a one-shot burn, so a merely TEMPORARY block heals itself. The live state goes to a status file.
package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

// WSPoolSNI is the exported (config) form of a pool SNI passed from main: the domain,
// its base64 ECHConfigList (empty = none), and request path (empty = "/").
type WSPoolSNI struct {
	Host string
	ECH  string
	Path string
}

// DialWSPoolCfg decodes the config's clean IP/SNI lists into a pool and returns a ws
// client that rotates over it. rotate is the proactive-rotation interval.
func DialWSPoolCfg(dev *tun.Device, keepalive time.Duration, obfs, cryptoOn bool, psk, cipher string, ips []string, snis []WSPoolSNI, rotate time.Duration, autoBurn bool, statusPath string, httpc bool, httpcMode string, warmStandby bool) (*TCP, error) {
	entries := make([]wsSNIEntry, 0, len(snis))
	for _, s := range snis {
		var ech []byte
		if s.ECH != "" {
			ech, _ = base64.StdEncoding.DecodeString(s.ECH) // validated in config
		}
		entries = append(entries, wsSNIEntry{host: s.Host, ech: ech, path: s.Path})
	}
	pool := newWSPoolFromCfg(ips, entries, autoBurn, statusPath)
	if pool == nil {
		return nil, errors.New("ws pool: need at least one IP and one SNI")
	}
	return DialWSPool(dev, keepalive, obfs, cryptoOn, psk, cipher, pool, rotate, httpc, httpcMode, warmStandby)
}

// wsSNIEntry is one fronting domain in the pool with its own ECH config and path.
type wsSNIEntry struct {
	host string
	ech  []byte
	path string
}

// Health FSM states for a pool entry (an IP, or an SNI host). A HEALTHY entry has NO record
// in the health map at all (absence == healthy); only suspect/dead entries are tracked.
const (
	stateSuspect = "suspect" // a probe found it guilty; pulled from rotation; retested on backoff
	stateDead    = "dead"    // failed enough retests; retested only on the slow interval
)

// suspectBackoff and deadRetest are the pool health-FSM timings —
// now operator-tunable package vars, defined with their defaults in tuning.go.

// healthRec tracks one non-healthy pool entry. fails counts failed retests since it entered
// suspect; nextRetest is the unix time the scheduler may probe it again.
type healthRec struct {
	state      string
	fails      int
	nextRetest int64
}

// wsPool holds the clean IP/SNI lists, the per-entry health FSM, and the active index.
// ipHealth/sniHealth track only the non-healthy entries (absent == healthy). Every change
// is snapshotted to statusPath. The pool is network-free (unit-testable): the prober and the
// retest scheduler live in tcp.go and drive the FSM through these pure methods.
type wsPool struct {
	mu          sync.Mutex
	writeMu     sync.Mutex // serializes the status file write+rename so concurrent writers don't race the shared .tmp
	ips         []string
	snis        []wsSNIEntry
	ipHealth    healthSet // absent == healthy
	sniHealth   healthSet // absent == healthy
	i, j        int       // current ip / sni index
	autoBurn    bool
	statusPath  string
	active      string
	rotDegraded bool        // true once the healthy-IP count fell below 2 (rotation paused); drives the degraded/restored event
	hb          int64       // unix-seconds of the carrier's lastRx — periodic liveness heartbeat
	dw          int64       // resolved dead-window in seconds — the single number a reader ages hb against
	events      []coreEvent // rolling ring of core-observed events (down/burn) for the panel log
	evSeq       int64       // monotonic sequence so the panel can consume each event exactly once
	wasDown     bool        // a genuine carrier down is pending its matching "up" (down/reconnect pairing)
	pinIP       string      // operator-pinned IP: current() forces it until it lands or is disproven
	pinSNI      string      // operator-pinned SNI: same
	pinTries    int         // failed attempts on the pinned combination; at pinFailRelease the pin goes
	// pinTook holds the health records the pin CLEARED, so a pin that turns out not to land can put the
	// pool back exactly as it found it. Clearing is the operator saying "try this one again"; it is not a
	// verdict, and a jump that never connected must not leave a dead entry looking healthy on the panel.
	pinTook map[string]*healthRec // "ip:<k>" / "sni:<k>" -> what was there before the pin
	now     func() int64          // injectable clock (unix seconds); overridden in tests
}

// suspectBackoff and deadRetest are operator-tunable package vars,
// defined with its default in tuning.go.

// coreEvent is one core-observed occurrence surfaced to the panel's system log: the CORE knows the
// real reason a carrier dropped or an edge was burned (it saw the actual error), so instead of the
// panel guessing, it records a stable machine `code` (+ optional detail) the panel maps to text.
type coreEvent struct {
	Seq    int64  `json:"seq"`
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`   // "down" (carrier dropped) | "up" (reconnected) | "burn" (edge sidelined) | "ech" (ECH self-heal)
	Code   string `json:"code"`   // stable reason category, e.g. ping_timeout / reset / tls / ws_upgrade / throttle
	Detail string `json:"detail"` // optional extra: the edge key, or a short raw-error snippet
}

const coreEventRing = 48 // keep the most recent N events in the status file

// event appends a core-observed event to the ring (newest kept) and flushes the status file so the
// node/panel can surface it. Safe to call from the client loops.
func (p *wsPool) event(kind, code, detail string) {
	p.mu.Lock()
	p.evSeq++
	p.events = append(p.events, coreEvent{Seq: p.evSeq, TS: time.Now().Unix(), Kind: kind, Code: code, Detail: detail})
	if len(p.events) > coreEventRing {
		p.events = p.events[len(p.events)-coreEventRing:]
	}
	p.mu.Unlock()
	p.writeStatus()
}

// down records a genuine carrier drop (NOT an operator pin / proactive rotation) and arms the next
// successful (re)connect — via setActive — to emit a matching "up", so a pool down is always paired
// in the ring like the datagram coreStatus. Callers still classify the reason (code/detail).
func (p *wsPool) down(code, detail string) {
	p.mu.Lock()
	p.wasDown = true
	p.mu.Unlock()
	p.event("down", code, detail)
}

func newWSPool(ips []string, snis []wsSNIEntry, autoBurn bool, statusPath string) *wsPool {
	p := &wsPool{ips: ips, snis: snis,
		autoBurn: autoBurn, statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.ipHealth, p.sniHealth = newHealthSet(&p.now), newHealthSet(&p.now)
	p.writeStatus()
	return p
}

// healthMap returns the record map for the given axis ("ip" or "sni"). Caller holds the lock.
func (p *wsPool) healthMap(kind string) healthSet {
	if kind == "sni" {
		return p.sniHealth
	}
	return p.ipHealth
}

// current returns the active (ip, sni). It prefers a FULLY-HEALTHY combo, scanning forward from the
// current index so consecutive dials rotate for variety. With nothing fully healthy it never dead-ends:
// it falls back to the least-bad ip and sni, so the tunnel keeps trying while the retest scheduler works
// the blocked entries back to health. ok=false only if the pool has no IPs or no SNIs.
func (p *wsPool) current() (string, wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked()
}

// currentLocked is current() without taking the lock, so advance() can resolve the edge BEFORE and
// AFTER a step under one lock and answer whether the step actually changes what the carrier will dial.
// Caller holds the lock.
func (p *wsPool) currentLocked() (string, wsSNIEntry, bool) {
	if len(p.ips) == 0 || len(p.snis) == 0 {
		return "", wsSNIEntry{}, false
	}
	// A manual pin is a ONE-SHOT exact jump: while it is in force current() FORCES the chosen axis, so
	// the jump — and any warm-standby promotion during it — lands on EXACTLY that edge, never a
	// neighbour. It ends on EVIDENCE, never on a clock: pinApplied when the carrier lands, or the
	// verdict path once enough proven-dead rounds say it cannot.
	if p.pinIP != "" || p.pinSNI != "" {
		return p.resolvePinIPLocked(), p.resolvePinSNILocked(), true
	}
	n := len(p.ips) * len(p.snis)
	for k := 0; k < n; k++ {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if p.ipHealth.healthy(ip) && p.sniHealth.healthy(sni.host) {
			return ip, sni, true
		}
		p.stepLocked()
	}
	ip := p.bestIPLocked()
	sni := p.bestSNILocked()
	return ip, sni, true
}

// updateECH replaces the stored ECHConfigList for the pool SNI matching host with the fresh key the edge
// returned after an in-band self-heal, so the NEXT reconnect presents it directly instead of hitting the
// stale-key rejection again on every reconnect. Returns true only when the stored key actually changed,
// which gives the caller a transition gate — one event per rotation, and concurrent healers converge.
func (p *wsPool) updateECH(host string, ech []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.snis {
		if p.snis[i].host == host {
			if bytes.Equal(p.snis[i].ech, ech) {
				return false
			}
			p.snis[i].ech = ech
			return true
		}
	}
	return false
}

// activeSep joins the two halves of a pooled carrier's status descriptor ("<ip> · <sni>"). The same
// separator splits the IP back out in current(), so a single const keeps producer and parser in
// lockstep — change it here and both sides move together.
const activeSep = " · "

// activeLabel builds the status-file "active edge" string for an (ip, sni) combo.
func activeLabel(ip, host string) string { return ip + activeSep + host }

// setActive records the edge the client is ACTUALLY carrying data on right now, for the status file's
// live "active edge" and the panel's auto-switch log. current() is deliberately NOT the place for it:
// current() also picks a warm STANDBY's edge, so letting it write p.active would show the standby
// instead of the live carrier. An empty combo is ignored, so a not-yet-connected state blanks nothing.
func (p *wsPool) setActive(combo string) {
	if combo == "" {
		return
	}
	p.mu.Lock()
	changed := p.active != combo
	p.active = combo
	pending := p.wasDown // a genuine down is awaiting its matching recovery
	p.wasDown = false
	p.mu.Unlock()
	if pending {
		p.event("up", "reconnect", combo) // recovered after a real drop; event() flushes the status file
	} else if changed {
		p.writeStatus()
	}
}

// resolvePinIPLocked returns the IP current() should use: the pinned one (absolute) if it still
// exists, else a healthy-preferred choice for the free axis (and the stale pin is dropped). Caller
// holds the lock.
func (p *wsPool) resolvePinIPLocked() string {
	if p.pinIP != "" {
		for _, ip := range p.ips {
			if ip == p.pinIP {
				return ip
			}
		}
		p.pinIP = "" // pinned IP was removed from the pool -> forget it
	}
	return p.healthyOrBestIPLocked()
}

func (p *wsPool) resolvePinSNILocked() wsSNIEntry {
	if p.pinSNI != "" {
		for _, s := range p.snis {
			if s.host == p.pinSNI {
				return s
			}
		}
		p.pinSNI = ""
	}
	return p.healthyOrBestSNILocked()
}

// healthyOrBestIPLocked returns the first healthy IP, else the least-bad one. Caller holds the lock.
func (p *wsPool) healthyOrBestIPLocked() string {
	for _, ip := range p.ips {
		if p.ipHealth.healthy(ip) {
			return ip
		}
	}
	return p.bestIPLocked()
}

func (p *wsPool) healthyOrBestSNILocked() wsSNIEntry {
	for _, s := range p.snis {
		if p.sniHealth.healthy(s.host) {
			return s
		}
	}
	return p.bestSNILocked()
}

// isPinned reports whether a manual pin is still in its (short) force window, during which
// proactive rotation is held off so the jump lands exactly. After the window it returns false
// and normal rotation resumes.
func (p *wsPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinIP != "" || p.pinSNI != ""
}

// bestIPLocked / bestSNILocked return the least-bad entry for the current() fallback: a
// healthy one if any, else the tracked entry with the soonest nextRetest, preferring suspect
// over dead. Caller holds the lock; the underlying slice is non-empty.
func (p *wsPool) bestIPLocked() string { return p.ipHealth.best(p.ips) }

func (p *wsPool) bestSNILocked() wsSNIEntry {
	best := p.snis[0]
	bt, bn := p.tierLocked("sni", best.host)
	for _, s := range p.snis[1:] {
		if t, n := p.tierLocked("sni", s.host); t < bt || (t == bt && n < bn) {
			best, bt, bn = s, t, n
		}
	}
	return best
}

// tierLocked ranks an entry for the current() fallback: 0 healthy, 1 suspect, 2 dead, with
// its nextRetest as the tiebreak within a tier. Caller holds the lock.
func (p *wsPool) tierLocked(kind, key string) (tier int, next int64) {
	return p.healthMap(kind).tier(key)
}

// stepLocked advances to the next (ip, sni) combination (caller holds the lock).
func (p *wsPool) stepLocked() {
	p.j++
	if p.j >= len(p.snis) {
		p.j = 0
		p.i++
		if p.i >= len(p.ips) {
			p.i = 0
		}
	}
}

// advance rotates to the next combination and reports whether the edge the carrier would actually DIAL
// changed. With every other combination burned a step lands straight back on the same edge, and a caller
// that drops the live connection anyway pays a re-dial and a traffic gap every interval for nothing. The
// comparison resolves through currentLocked() both times: the cursor always moves, the resolved edge not.
func (p *wsPool) advance() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	beforeIP, beforeSNI, okBefore := p.currentLocked()
	p.stepLocked()
	afterIP, afterSNI, okAfter := p.currentLocked()
	if !okBefore || !okAfter {
		return false // empty pool — there is nothing to rotate onto
	}
	return beforeIP != afterIP || beforeSNI.host != afterSNI.host
}

// hasHealthyEdgeOtherThan reports whether the pool can currently produce a HEALTHY (ip · sni) combo that
// is not `combo`. Read-only — no cursor movement, no status write — because the warm-standby manager asks
// it every rotation tick: its standby may sit on the active's own edge, so has anything healed since? It
// mirrors currentLocked's rule (both axes unburned), since an SNI-only move on one IP is a real rotation.
func (p *wsPool) hasHealthyEdgeOtherThan(combo string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ip := range p.ips {
		if !p.ipHealth.healthy(ip) {
			continue
		}
		for _, sni := range p.snis {
			if p.sniHealth.healthy(sni.host) && ip+activeSep+sni.host != combo {
				return true
			}
		}
	}
	return false
}

// aimStandby positions the rotation cursor for the WARM STANDBY dial: onto a HEALTHY edge whose IP
// differs from the LIVE ACTIVE edge's, so the standby can never collide with it. A blind advance() will
// not do — the shared cursor is not anchored to the active edge, so a plain step can walk the standby
// onto the active's own IP, and promoting that is no switch at all. Falls back to a plain step.
func (p *wsPool) aimStandby() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ips) == 0 || len(p.snis) == 0 {
		return
	}
	activeIP := p.active // p.active is "ip · sni"; take the IP before the separator
	if k := strings.Index(activeIP, activeSep); k >= 0 {
		activeIP = activeIP[:k]
	}
	for off := 1; off <= len(p.ips); off++ {
		idx := (p.i + off) % len(p.ips)
		if ip := p.ips[idx]; ip != activeIP && p.ipHealth.healthy(ip) {
			p.i = idx // a healthy edge on a DIFFERENT IP than the active — the standby's home
			p.aimNextHealthySNILocked()
			return
		}
	}
	p.stepLocked() // no distinct healthy IP available — degrade to a plain step (still varies the SNI axis)
}

// aimNextHealthySNILocked advances the SNI cursor to the next HEALTHY domain, wrapping. Without it
// aimStandby's IP-anchoring path writes only p.i and rotation degrades to IP-only, so a flagged domain is
// never rotated off and one permanently-reused SNI becomes a stable fingerprint. Landing on a HEALTHY SNI
// is deliberate: current() calls stepLocked on an unhealthy combo, walking off the IP just picked.
func (p *wsPool) aimNextHealthySNILocked() {
	for off := 1; off <= len(p.snis); off++ {
		idx := (p.j + off) % len(p.snis)
		if p.sniHealth.healthy(p.snis[idx].host) {
			p.j = idx
			return
		}
	}
}

// advanceIP / advanceSNI rotate a single dimension (manual "rotate now, IP only" /
// "rotate now, SNI only" from the panel). current() still skips unhealthy entries, so a
// bump that lands on a suspect/dead one is passed over on the next dial.
func (p *wsPool) advanceIP() {
	p.mu.Lock()
	if len(p.ips) > 0 {
		p.i = (p.i + 1) % len(p.ips)
	}
	p.mu.Unlock()
}

// advanceEdgeFreshRow moves to the next EDGE and starts its row clean, dropping every SNI burn.
//
// Both halves are needed. A whole row of SNIs failing on one edge convicts the EDGE — the SNIs were
// never shown to be bad on their own, only in combination with it, so on the next edge they each deserve
// the fresh try that is the whole experiment. And carrying the burns forward is not merely unfair, it
// STALLS the walk: with every SNI condemned, currentLocked finds no healthy combo, falls through to
// best-effort and hands back the edge the cursor just left.
func (p *wsPool) advanceEdgeFreshRow() {
	p.mu.Lock()
	if len(p.ips) > 0 {
		p.i = (p.i + 1) % len(p.ips)
	}
	cleared := len(p.sniHealth.recs) > 0
	p.sniHealth = newHealthSet(&p.now)
	p.mu.Unlock()
	if cleared {
		p.writeStatus()
	}
}

func (p *wsPool) advanceSNI() {
	p.mu.Lock()
	if len(p.snis) > 0 {
		p.j = (p.j + 1) % len(p.snis)
	}
	p.mu.Unlock()
}

// markSuspect moves a HEALTHY entry into suspect (out of active rotation, scheduled for a
// +30s retest). A no-op when autoBurn is off (a manual-only pool never auto-sidelines an
// entry) or when the entry is already tracked — a fresh live failure must not reset an
// in-progress backoff; the retest scheduler owns the entry's cadence from here.
// eligibleSNIs is how many SNIs the rotation could actually try right now: the healthy ones, or the
// whole list when none is tracked. Read BEFORE a burn to size one lap of the matrix — a condemned SNI
// cannot be tried, so counting the raw list would call a lap complete that never happened and walk the
// edge off an SNI that never varied.
func (p *wsPool) eligibleSNIs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.snis {
		if p.sniHealth.healthy(e.host) {
			n++
		}
	}
	return n
}

func (p *wsPool) markSuspect(kind, key, reason string) {
	if !p.autoBurn {
		return
	}
	p.mu.Lock()
	fresh := p.healthMap(kind).sideline(key)
	p.mu.Unlock()
	if fresh {
		p.event("burn", reason, kind+":"+key) // only log the transition into suspect, not repeats
	}
	p.writeStatus()
	if fresh && kind == "ip" {
		p.reassessRotation()
	}
}

// restorePinTookLocked puts back the health records the pin cleared. Called only when the pin is
// abandoned WITHOUT landing: the clear was the operator asking for a fresh try, and a try that never
// happened must not leave the pool believing a dead entry recovered. A landed pin keeps the clear --
// there the entry really did prove itself. Caller holds the lock.
func (p *wsPool) restorePinTookLocked() {
	for k, rec := range p.pinTook {
		if rec == nil {
			continue // it was healthy before the pin; leave it healthy
		}
		if kind, key, found := strings.Cut(k, ":"); found {
			p.healthMap(kind).recs[key] = rec
		}
	}
	clear(p.pinTook)
}

// pinAttemptFailed is the core's OWN evidence about a pin, and the reason a pin needs no clock: it
// watches the dial to the pinned edge fail, which says more about that exact edge than the node's tunnel
// probe can, and says it in one timeout instead of two sweeps plus a settle window. At pinFailRelease
// the pin is released so normal rotation resumes; a landing resets the count (pinApplied clears the pin
// outright, so only a not-yet-landed pin is ever counting).
//
// A no-op unless the pin actually targets what just failed — under warm standby a STANDBY dial to some
// other edge is failing beside the pinned one, and that says nothing about the operator's pick.
func (p *wsPool) pinAttemptFailed(ip, host string) {
	p.mu.Lock()
	counted := (p.pinIP != "" && p.pinIP == ip) || (p.pinSNI != "" && p.pinSNI == host)
	released := false
	if counted {
		if p.pinTries++; p.pinTries >= pinFailRelease {
			p.restorePinTookLocked()
			p.pinIP, p.pinSNI, p.pinTries = "", "", 0
			released = true
		}
	}
	p.mu.Unlock()
	if released {
		p.writeStatus()
		p.event("pool", "pin_dropped", "cannot-land")
	}
}

// releasePin drops any manual pin outright, on both axes. The counted release the verdict path performs
// once a pin has absorbed its second opinion — see burnAdvanceWS and rotationController.fail, which do
// the same thing for the other four carriers.
func (p *wsPool) releasePin() {
	p.mu.Lock()
	changed := p.pinIP != "" || p.pinSNI != ""
	if changed {
		p.restorePinTookLocked() // abandoned without landing -- see restorePinTookLocked
	}
	p.pinIP, p.pinSNI = "", ""
	p.mu.Unlock()
	if changed {
		p.writeStatus()
		p.event("pool", "pin_dropped", "tun-probe")
	}
}

// reassessRotation emits a ONE-SHOT event when the pool crosses the "can it still rotate its IP axis?"
// boundary. IP rotation needs >=2 HEALTHY ip endpoints; with only one left the tunnel silently stops
// switching edges, which reads in the log as "rotation stopped" — so the transition ("degraded") and its
// recovery ("restored") are surfaced. No-op for a single-ip pool or an unmoved boundary; idempotent.
func (p *wsPool) reassessRotation() {
	p.mu.Lock()
	if len(p.ips) < 2 {
		p.mu.Unlock()
		return
	}
	healthy := 0
	for _, ip := range p.ips {
		if p.ipHealth.healthy(ip) {
			healthy++
		}
	}
	degraded := healthy < 2
	if degraded == p.rotDegraded {
		p.mu.Unlock()
		return
	}
	p.rotDegraded = degraded
	p.mu.Unlock()
	detail := strconv.Itoa(healthy) + "/" + strconv.Itoa(len(p.ips))
	if degraded {
		p.event("pool", "degraded", detail) // only one healthy edge left — rotation is paused
	} else {
		p.event("pool", "restored", detail) // a second edge recovered — rotation can resume
	}
}

// succeeded clears the health records for a combo that just connected: a live success proves
// both its IP and its SNI healthy right now. Only writes the status file if something changed.
func (p *wsPool) succeeded(ip, host string) {
	p.mu.Lock()
	changed := p.ipHealth.clear(ip)
	changed = p.sniHealth.clear(host) || changed
	p.mu.Unlock()
	if changed {
		p.writeStatus()
		p.reassessRotation()
	}
}

// retestResult feeds a probe outcome for a tracked entry into the FSM: ANY success clears it
// back to healthy; a failure walks the suspect backoff and eventually drops it to dead.
func (p *wsPool) retestResult(kind, key string, success bool) {
	p.mu.Lock()
	m := p.healthMap(kind)
	r := m.rec(key)
	if r == nil { // cleared from under us (e.g. a concurrent live success) — nothing to do
		p.mu.Unlock()
		return
	}
	if success {
		m.clear(key)
	} else {
		m.retestFailed(r)
	}
	p.mu.Unlock()
	if success {
		// A background probe recovered a sidelined edge/SNI (suspect|dead -> healthy). Emit a discrete
		// heal event so the operator sees the self-heal in the log, not just a silent status-file flip.
		p.event("heal", "retest", kind+":"+key) // event() also writes the status file
	} else {
		p.writeStatus()
	}
	if kind == "ip" {
		p.reassessRotation() // a recovered/dead ip may have crossed the "can still rotate" boundary
	}
}

// retestSpec is one entry the scheduler should probe now, paired with a partner on the OTHER
// axis to probe it against (a known-healthy partner when one exists, else the current active
// partner) so the probe changes only the entry under test.
type retestSpec struct {
	kind string // "ip" or "sni": which axis the entry belongs to
	key  string
	ip   string     // the IP to dial
	sni  wsSNIEntry // the SNI to present
}

// dueRetests returns the tracked entries whose nextRetest has arrived, each paired with a
// partner to probe against. The scheduler runs one probe per spec and feeds the boolean back
// through retestResult.
func (p *wsPool) dueRetests() []retestSpec {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []retestSpec
	for _, ip := range p.ips {
		if p.ipHealth.due(ip) {
			out = append(out, retestSpec{kind: "ip", key: ip, ip: ip, sni: p.partnerSNILocked()})
		}
	}
	for _, s := range p.snis {
		if p.sniHealth.due(s.host) {
			out = append(out, retestSpec{kind: "sni", key: s.host, ip: p.partnerIPLocked(), sni: s})
		}
	}
	return out
}

// partnerSNILocked / partnerIPLocked pick a KNOWN-HEALTHY partner to retest an entry against,
// falling back to the currently-selected one when none is healthy. Caller holds the lock.
func (p *wsPool) partnerSNILocked() wsSNIEntry {
	for _, s := range p.snis {
		if p.sniHealth.healthy(s.host) {
			return s
		}
	}
	return p.snis[p.j%len(p.snis)]
}

func (p *wsPool) partnerIPLocked() string {
	for _, ip := range p.ips {
		if p.ipHealth.healthy(ip) {
			return ip
		}
	}
	return p.ips[p.i%len(p.ips)]
}

// altHealthySNI returns a healthy SNI other than exclude (the differential probe's
// "same IP, different SNI" arm); ok=false when none exists.
func (p *wsPool) altHealthySNI(exclude string) (wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.snis {
		if s.host != exclude && p.sniHealth.healthy(s.host) {
			return s, true
		}
	}
	return wsSNIEntry{}, false
}

// altHealthyIP returns a healthy IP other than exclude (the differential probe's
// "different IP, same SNI" arm); ok=false when none exists.
func (p *wsPool) altHealthyIP(exclude string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ip := range p.ips {
		if ip != exclude && p.ipHealth.healthy(ip) {
			return ip, true
		}
	}
	return "", false
}

// probeAllNow pulls EVERY suspect/dead entry's retest forward to now, so the scheduler
// probes them all on its next tick. Backs the panel's "probe now" control (a signal can't
// carry a specific key, so this sweeps them all — cheap TLS-only probes).
func (p *wsPool) probeAllNow() {
	p.mu.Lock()
	p.ipHealth.probeAllNow()
	p.sniHealth.probeAllNow()
	p.mu.Unlock()
}

// selectEntry PINS a specific edge as the active one on its axis: current() forces the chosen edge until
// the carrier lands on it (pinApplied clears the pin) or the evidence disproves it. So it is "jump
// exactly here and keep trying until connected" — it survives a transient outage but self-releases on
// success and on a dead edge. It also clears any suspect/dead mark. False if the key is unknown.
func (p *wsPool) selectEntry(kind, key string) bool {
	p.mu.Lock()
	ok := false
	if p.pinTook == nil {
		p.pinTook = map[string]*healthRec{}
	}
	if kind == "sni" {
		for idx, s := range p.snis {
			if s.host == key {
				p.j = idx
				p.pinSNI = key
				p.pinTook["sni:"+key] = p.sniHealth.rec(key)
				p.sniHealth.clear(key)
				ok = true
				break
			}
		}
	} else {
		for idx, ip := range p.ips {
			if ip == key {
				p.i = idx
				p.pinIP = key
				p.pinTook["ip:"+key] = p.ipHealth.rec(key)
				p.ipHealth.clear(key)
				ok = true
				break
			}
		}
	}
	if ok {
		p.pinTries = 0
		// `active` follows the pin, before any dial. It is what the NODE keys its verdict on, and while a
		// pin is in force the tunnel really is trying THAT combination -- leaving it on the previous one
		// meant a verdict measured during the jump named an edge nothing was attempting, and burned it.
		// The direct pool has always done this (peerPoolStatus publishes the cursor, which selectEntry
		// moves); the edge pool published a string only a successful dial ever wrote.
		if ip, sni, got := p.currentLocked(); got {
			p.active = activeLabel(ip, sni.host)
		}
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
		if kind == "ip" {
			// Clearing an IP's burn just raised the healthy-IP count and may have crossed the "can it
			// still rotate?" boundary back up. succeeded()/retestResult() reassess here too; selectEntry
			// must as well, or a "restored" event is never emitted and rotDegraded stays stuck true —
			// which then swallows the NEXT degraded/restored transition. (Idempotent: no-op if unmoved.)
			p.reassessRotation()
		}
	}
	return ok
}

// pinApplied clears a manual pin once the carrier has ACTUALLY landed on the pinned edge, so a pin
// behaves as "jump there and keep retrying until connected" (surviving a transient outage — see
// yet releases the instant it succeeds instead of freezing rotation.
// Each axis is cleared independently: an IP-only pin releases when the live IP matches, likewise SNI.
func (p *wsPool) pinApplied(ip, host string) {
	p.mu.Lock()
	p.pinTries = 0
	clear(p.pinTook) // it landed: the entry proved itself, so the clear stands
	changed := false
	if p.pinIP != "" && p.pinIP == ip {
		p.pinIP = ""
		changed = true
	}
	if p.pinSNI != "" && p.pinSNI == host {
		p.pinSNI = ""
		changed = true
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

// pinMatches reports whether a carrier that came up on (ip, host) satisfies EVERY axis of the live
// pin — the read-only twin of pinApplied, for deciding whether a connection may become the active at
// all. A dial that resolved its edge before the pin existed does not satisfy it, and adopting such a
// connection lands the operator somewhere they did not pick. True when no pin is in force.
func (p *wsPool) pinMatches(ip, host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pinIP != "" && p.pinIP != ip {
		return false
	}
	if p.pinSNI != "" && p.pinSNI != host {
		return false
	}
	return true
}

// cmdPath is the sidecar file the node writes its commands into. Empty when the pool has no status
// path (nothing to poll).
func (p *wsPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

// readCmd consumes this pool's pending command, if any, and defaults the PIN axis. A pin that names no
// axis is an edge pin: that is the axis the panel's button has always meant, and "" would silently look
// up an entry in the SNI map.
func (p *wsPool) readCmd() (c poolCmd, ok bool) {
	if c, ok = readPoolCmd(p.cmdPath()); !ok {
		return c, false
	}
	if c.Kind != "sni" {
		c.Kind = "ip"
	}
	return c, true
}

// activeCombo splits the published "active" label back into the edge and the SNI it was published
// with. Empty strings when nothing is active yet.
func (p *wsPool) activeCombo() (ip, sni string) {
	p.mu.Lock()
	a := p.active
	p.mu.Unlock()
	if i := strings.Index(a, activeSep); i >= 0 {
		return a[:i], a[i+len(activeSep):]
	}
	return a, ""
}

// clearBurn drops an entry's health record outright, so a proven-carrying combo is healthy again
// immediately instead of waiting out its retest ladder. Reports whether anything was actually cleared.
func (p *wsPool) clearBurn(kind, key string) bool {
	p.mu.Lock()
	had := p.healthMap(kind).clear(key)
	p.mu.Unlock()
	if had {
		p.writeStatus()
	}
	return had
}

// echCmdPath is the sidecar file the node writes a LIVE ECH-key update into (JSON {"snis":{host:base64}}).
// The panel pushes a freshly-fetched ECHConfigList here so the RUNNING pool adopts it without a rebuild.
func (p *wsPool) echCmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".echcmd"
}

// readECHCmd consumes a pending live ECH-key update (base64 ECHConfigList per SNI host) and hot-swaps it
// into the pool via updateECH, so the NEXT dial presents the fresh key — no rebuild, no TUN drop. Returns
// the hosts whose key actually changed, and removes the file so it fires once. The proactive counterpart
// to the in-band self-heal: the panel pushes the key BEFORE the old one fails.
func (p *wsPool) readECHCmd() []string {
	cp := p.echCmdPath()
	if cp == "" {
		return nil
	}
	data, err := os.ReadFile(cp)
	if err != nil {
		return nil
	}
	os.Remove(cp)
	var c struct {
		SNIs map[string]string `json:"snis"`
	}
	if json.Unmarshal(data, &c) != nil || len(c.SNIs) == 0 {
		return nil
	}
	var changed []string
	for host, b64 := range c.SNIs {
		ech, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if derr != nil || len(ech) == 0 {
			continue
		}
		if p.updateECH(host, ech) {
			changed = append(changed, host)
		}
	}
	return changed
}

// healthStatus is one entry's health as published to the status file.
type healthStatus struct {
	Key        string `json:"key"`
	Kind       string `json:"kind"`  // "ip" | "sni"
	State      string `json:"state"` // "healthy" | "suspect" | "dead"
	Fails      int    `json:"fails"`
	NextRetest int64  `json:"next_retest_unix"`
}

// writeStatus snapshots {active, health, ts} to statusPath (best effort) so the node/panel can show
// the live edge and drive the pool. health carries the full per-entry FSM state (state/fails/
// next_retest), which is what every reader actually uses.
func (p *wsPool) writeStatus() {
	if p.statusPath == "" {
		return
	}
	// Hold writeMu across BOTH the snapshot and the file write, so two concurrent writers cannot snapshot
	// in one order and win the write in the reverse order — an older snapshot must never overwrite a newer
	// file. p.mu is always released before any caller reaches writeStatus, so writeMu→p.mu never inverts.
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	health := make([]healthStatus, 0, len(p.ips)+len(p.snis))
	for _, ip := range p.ips {
		hs := healthStatus{Key: ip, Kind: "ip", State: "healthy"}
		if r := p.ipHealth.rec(ip); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		health = append(health, hs)
	}
	for _, s := range p.snis {
		hs := healthStatus{Key: s.host, Kind: "sni", State: "healthy"}
		if r := p.sniHealth.rec(s.host); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		health = append(health, hs)
	}
	evs := append([]coreEvent(nil), p.events...) // copy so the marshal runs outside the lock
	st := struct {
		Active string         `json:"active"`
		Health []healthStatus `json:"health"`
		Events []coreEvent    `json:"events"`
		HB     int64          `json:"hb"`
		DW     int64          `json:"dw"`
		TS     int64          `json:"ts"`
	}{Active: p.active, Health: health, Events: evs, HB: p.hb, DW: p.dw, TS: time.Now().Unix()}
	p.mu.Unlock()
	if data, err := json.Marshal(st); err == nil {
		// writeMu already held across the snapshot above (serializes writers AND orders snapshot->write).
		writeFileAtomic(p.statusPath, data, 0o644)
	}
}

// beat records the carrier's lastRx (unix-seconds) into the pool status and flushes it, so a reader can
// tell a live-but-idle pooled tunnel (hb advancing each keepalive) from a dead one (hb frozen) without
// ICMP. Nil-safe and no-op without a status path.
func (p *wsPool) beat(sec int64) {
	if p == nil || p.statusPath == "" {
		return
	}
	p.mu.Lock()
	p.hb = sec
	p.mu.Unlock()
	p.writeStatus()
}

// setDW publishes the carrier's resolved dead-window (seconds), so a reader ages hb against the same
// number the core uses. Called once at Run. Nil-safe and no-op without a status path.
func (p *wsPool) setDW(secs int64) {
	if p == nil || p.statusPath == "" {
		return
	}
	p.mu.Lock()
	p.dw = secs
	p.mu.Unlock()
	p.writeStatus()
}
