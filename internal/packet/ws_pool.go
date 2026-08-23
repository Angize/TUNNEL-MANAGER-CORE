package packet

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/tun"
)

type WSPoolSNI struct {
	Host string
	ECH  string
	Path string
}

func DialWSPoolCfg(dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, ips []string, snis []WSPoolSNI, rotate time.Duration, httpc bool, httpcMode string) (*TCP, error) {
	entries := make([]wsSNIEntry, 0, len(snis))
	for _, s := range snis {
		var ech []byte
		if s.ECH != "" {
			ech, _ = base64.StdEncoding.DecodeString(s.ECH)
		}
		entries = append(entries, wsSNIEntry{host: s.Host, ech: ech, path: s.Path})
	}
	pool := newWSPoolFromCfg(ips, entries)
	if pool == nil {
		return nil, errors.New("ws pool: need at least one IP and one SNI")
	}
	return DialWSPool(dev, obfs, cryptoOn, psk, cipher, pool, rotate, httpc, httpcMode)
}

type wsSNIEntry struct {
	host string
	ech  []byte
	path string
}

const (
	stateSuspect = "suspect"
	stateDead    = "dead"
)

type healthRec struct {
	state      string
	fails      int
	nextRetest int64
}

type wsPool struct {
	mu          sync.Mutex
	ips         []string
	snis        []wsSNIEntry
	ipHealth    healthSet
	sniHealth   healthSet
	i, j        int
	burns       atomic.Uint64
	rotDegraded bool
	chosen      string
	pinIP       string
	pinSNI      string

	pinTook map[string]*healthRec
	now     func() int64

	ev    func(kind, code, detail string)
	flush func()
}

// Where this pool's events go, and how it asks the tunnel's one status file to be republished. Same
// wiring as PeerPool: the carrier owns the file, the pool only owns the endpoints.
func (p *wsPool) attach(ev func(kind, code, detail string), flush func()) {
	p.mu.Lock()
	p.ev, p.flush = ev, flush
	p.mu.Unlock()
	p.publish()
}

func (p *wsPool) publish() {
	p.mu.Lock()
	f := p.flush
	p.mu.Unlock()
	if f != nil {
		f()
	}
}

type coreEvent struct {
	Seq    int64  `json:"seq"`
	TS     int64  `json:"ts"`
	Kind   string `json:"kind"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

const coreEventRing = 48

func (p *wsPool) event(kind, code, detail string) {
	p.mu.Lock()
	ev := p.ev
	p.mu.Unlock()
	if ev != nil {
		ev(kind, code, detail)
	}
}

func newWSPool(ips []string, snis []wsSNIEntry) *wsPool {
	p := &wsPool{ips: ips, snis: snis, now: func() int64 { return time.Now().Unix() }}
	p.ipHealth, p.sniHealth = newHealthSet(&p.now), newHealthSet(&p.now)
	return p
}

func (p *wsPool) healthMap(kind string) healthSet {
	if kind == "sni" {
		return p.sniHealth
	}
	return p.ipHealth
}

func (p *wsPool) current() (string, wsSNIEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentLocked()
}

func (p *wsPool) currentLocked() (string, wsSNIEntry, bool) {
	if len(p.ips) == 0 || len(p.snis) == 0 {
		return "", wsSNIEntry{}, false
	}

	if p.pinIP != "" || p.pinSNI != "" {
		return p.resolvePinIPLocked(), p.resolvePinSNILocked(), true
	}

	// A committed combination is stable, not immortal: if it has since been condemned, the commitment
	// is stale and the scan below has to run. Without this the walk burns an entry and the very next
	// dial goes straight back to it.
	if p.chosen != "" {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if activeLabel(ip, sni.host) == p.chosen &&
			p.ipHealth.eligible(ip) && p.sniHealth.eligible(sni.host) {
			return ip, sni, true
		}
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

	for k := 0; k < n; k++ {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if p.ipHealth.eligible(ip) && p.sniHealth.eligible(sni.host) {
			return ip, sni, true
		}
		p.stepLocked()
	}

	ip := p.bestIPLocked()
	sni := p.bestSNILocked()
	p.chosen = ""
	return ip, sni, true
}

func (p *wsPool) commitLocked() bool {
	ip := p.ips[p.i%len(p.ips)]
	sni := p.snis[p.j%len(p.snis)]
	if !p.ipHealth.eligible(ip) || !p.sniHealth.eligible(sni.host) {
		return false
	}
	p.chosen = activeLabel(ip, sni.host)
	return true
}

func (p *wsPool) stepToEligibleLocked() bool {
	n := len(p.ips) * len(p.snis)
	for k := 0; k < n; k++ {
		p.stepLocked()
		if p.commitLocked() {
			return true
		}
	}
	return false
}

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

const activeSep = " · "

func activeLabel(ip, host string) string { return ip + activeSep + host }

func (p *wsPool) resolvePinIPLocked() string {
	if p.pinIP != "" {
		for _, ip := range p.ips {
			if ip == p.pinIP {
				return ip
			}
		}
		p.pinIP = ""
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

func (p *wsPool) isPinned() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinIP != "" || p.pinSNI != ""
}

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

func (p *wsPool) tierLocked(kind, key string) (tier int, next int64) {
	return p.healthMap(kind).tier(key)
}

// Put the cursor on a combination. Compares the RAW cursor, not currentLocked(), which would resolve
// and step.
func (p *wsPool) keepCursorOn(ip, sni string) {
	if p == nil || ip == "" {
		return
	}
	p.mu.Lock()
	moved := false
	if p.ips[p.i%len(p.ips)] != ip || p.snis[p.j%len(p.snis)].host != sni {
		for i, e := range p.ips {
			if e != ip {
				continue
			}
			for j, s := range p.snis {
				if s.host == sni {
					p.i, p.j, p.chosen = i, j, activeLabel(ip, sni)
					moved = true
				}
			}
		}
	}
	p.mu.Unlock()
	if moved {
		p.publish()
	}
}

// The EDGE is the digit that varies every step: an edge is cheap to lose and cheap to get back, and
// it is the thing the filter actually blocks. The domain turns only once every edge under it has been
// tried, because losing a domain loses it on every edge at once.
func (p *wsPool) stepLocked() {
	p.chosen = ""
	p.i++
	if p.i >= len(p.ips) {
		p.i = 0
		p.j++
		if p.j >= len(p.snis) {
			p.j = 0
		}
	}
}

func (p *wsPool) advance() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	beforeIP, beforeSNI, ok := p.currentLocked()
	if !ok {
		return false
	}
	if p.pinIP != "" || p.pinSNI != "" {
		return false
	}
	if !p.stepToEligibleLocked() {
		return false
	}
	ip := p.ips[p.i%len(p.ips)]
	sni := p.snis[p.j%len(p.snis)]
	return ip != beforeIP || sni.host != beforeSNI.host
}

// Reports where the cursor landed, and "" when there was nowhere to go: one entry on that axis, so the
// step is a no-op and there is nothing to announce.
func (p *wsPool) advanceIP() (now string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.chosen = ""
	if len(p.ips) < 2 {
		return ""
	}
	p.i = (p.i + 1) % len(p.ips)
	return p.ips[p.i]
}

func (p *wsPool) advanceSNI() (now string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.chosen = ""
	if len(p.snis) < 2 {
		return ""
	}
	p.j = (p.j + 1) % len(p.snis)
	return p.snis[p.j].host
}

// A fresh domain deserves a fresh row of edges: the burns under the previous one said nothing about
// this one.
func (p *wsPool) restoreIPs() {
	p.mu.Lock()
	cleared := len(p.ipHealth.recs) > 0
	p.ipHealth = newHealthSet(&p.now)
	p.mu.Unlock()
	if cleared {
		p.publish()
		p.reassessRotation()
	}
}

func (p *wsPool) activeSNIIdx() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.j
}

func (p *wsPool) burnCount() uint64 { return p.burns.Load() }

// The digit a fail condemns every round.
type wsEdges struct{ p *wsPool }

func (a wsEdges) eligibleCount() int { return a.p.eligibleIPs() }
func (a wsEdges) burnCount() uint64  { return a.p.burnCount() }
func (a wsEdges) restoreAll()        { a.p.restoreIPs() }

// The digit that turns once a whole row of edges has been tried.
type wsSNIs struct{ p *wsPool }

func (a wsSNIs) activeIdx() int { return a.p.activeSNIIdx() }

func (p *wsPool) comboCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ips) * len(p.snis)
}

func (p *wsPool) eligibleIPs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ipHealth.countEligible(p.ips)
}

func (p *wsPool) ipsCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ips)
}

func (p *wsPool) markSuspect(kind, key, reason string) {
	if key == "" {
		return // nothing was measured, so there is nobody to condemn
	}
	p.mu.Lock()
	// A pinned entry holds its health record in pinTook; burning it here would be undone the moment the
	// pin is restored. The pin's own counter releases it instead. Same rule as PeerPool.nextEndpoint.
	if (kind == "ip" && p.pinIP == key) || (kind == "sni" && p.pinSNI == key) {
		p.mu.Unlock()
		return
	}
	fresh := p.healthMap(kind).burn(key)
	p.mu.Unlock()
	if fresh {
		p.burns.Add(1)
		p.event("burn", reason, kind+":"+key)
	}
	p.publish()
	if fresh && kind == "ip" {
		p.reassessRotation()
	}
}

func (p *wsPool) pinnedOnLocked(kind string) string {
	if kind == "sni" {
		return p.pinSNI
	}
	return p.pinIP
}

// Hand an axis' pinned entry its health record back and forget the stash. The pin field itself belongs
// to the caller: selectEntry replaces it, the two drops empty it.
func (p *wsPool) unstashLocked(kind string) {
	live := p.pinnedOnLocked(kind)
	if live == "" {
		return
	}
	k := kind + ":" + live
	if rec := p.pinTook[k]; rec != nil {
		p.healthMap(kind).recs[live] = rec
	}
	delete(p.pinTook, k)
}

// Both picks end at once. Only the tun probe gets to do this: it measures the PAIR, so both halves have
// been judged together.
func (p *wsPool) dropPin(reason string, matched func() bool) bool {
	p.mu.Lock()
	hit := matched()
	if hit {
		p.unstashLocked("ip")
		p.unstashLocked("sni")
		clear(p.pinTook)
		p.pinIP, p.pinSNI = "", ""
	}
	p.mu.Unlock()
	if hit {
		p.publish()
		p.event("pool", "pin_dropped", "edge:"+reason)
	}
	return hit
}

// ONE axis' pick ends. `key` empty means whatever is pinned there.
func (p *wsPool) dropPinAxis(kind, key, reason string) bool {
	p.mu.Lock()
	live := p.pinnedOnLocked(kind)
	hit := live != "" && (key == "" || live == key)
	if hit {
		p.unstashLocked(kind)
		if kind == "sni" {
			p.pinSNI = ""
		} else {
			p.pinIP = ""
		}
	}
	p.mu.Unlock()
	if hit {
		p.publish()
		p.event("pool", "pin_dropped", kind+":"+reason)
	}
	return hit
}

// A refused dial says the EDGE did not open. TLS never started, so the domain was never sent and
// nothing was learned about it -- ending a domain pin here would throw away the operator's expensive
// pick over a cheap one. The domain is judged by the tun probe, on the lap.
func (p *wsPool) pinCannotLand(ip string) bool {
	return p.dropPinAxis("ip", ip, "cannot-land")
}

func (p *wsPool) releasePin() {
	p.dropPin("tun-probe", func() bool { return p.pinIP != "" || p.pinSNI != "" })
}

func (p *wsPool) reassessRotation() {
	p.mu.Lock()
	if len(p.ips) < 2 {
		p.mu.Unlock()
		return
	}

	reachable := p.ipHealth.countEligible(p.ips)
	degraded := reachable < 2
	if degraded == p.rotDegraded {
		p.mu.Unlock()
		return
	}
	p.rotDegraded = degraded
	p.mu.Unlock()
	detail := strconv.Itoa(reachable) + "/" + strconv.Itoa(len(p.ips))
	if degraded {
		p.event("pool", "degraded", detail)
	} else {
		p.event("pool", "restored", detail)
	}
}

// One entry's wait ends. Nothing is dialled: it re-enters the rotation and the tun probe judges it.
func (p *wsPool) retestNow(kind, key string) bool {
	p.mu.Lock()
	ok := p.healthMap(kind).retestNow(key)
	p.mu.Unlock()
	if ok {
		p.publish()
	}
	return ok
}

func (p *wsPool) selectEntry(kind, key string) bool {
	p.mu.Lock()
	idx := -1
	if kind == "sni" {
		for i, s := range p.snis {
			if s.host == key {
				idx = i
				break
			}
		}
	} else {
		for i, ip := range p.ips {
			if ip == key {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		p.mu.Unlock()
		return false
	}
	if p.pinTook == nil {
		p.pinTook = map[string]*healthRec{}
	}
	p.chosen = ""
	// Re-pinning what is already pinned must not stash again: the first pin cleared that record, so a
	// second stash saves nothing over the burn it is holding and the burn is gone for good.
	if p.pinnedOnLocked(kind) != key {
		p.unstashLocked(kind)
		p.pinTook[kind+":"+key] = p.healthMap(kind).rec(key)
		p.healthMap(kind).clear(key)
	}
	if kind == "sni" {
		p.j, p.pinSNI = idx, key
	} else {
		p.i, p.pinIP = idx, key
	}
	p.stepToCurrentLocked()
	p.mu.Unlock()
	p.publish()
	if kind == "ip" {
		p.reassessRotation()
	}
	return true
}

func (p *wsPool) pinLandedOn(ip, host string) {
	p.mu.Lock()
	changed := false

	if p.pinIP != "" && p.pinIP == ip {
		delete(p.pinTook, "ip:"+ip)
		p.pinIP = ""
		changed = true
	}
	if p.pinSNI != "" && p.pinSNI == host {
		delete(p.pinTook, "sni:"+host)
		p.pinSNI = ""
		changed = true
	}
	p.mu.Unlock()
	if changed {
		p.publish()
	}
}

func (p *wsPool) clearBurn(kind, key string) bool {
	p.mu.Lock()
	had := p.healthMap(kind).clear(key)
	p.mu.Unlock()
	if had {
		p.event("heal", "tun-probe", kind+":"+key)
		p.publish()

		if kind == "ip" {
			p.reassessRotation()
		}
	}
	return had
}

// The keys an ECH push actually changed. Reading the file is the carrier's job; this only applies it.
func (p *wsPool) applyECH(snis map[string]string) []string {
	var changed []string
	for host, b64 := range snis {
		ech, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil || len(ech) == 0 {
			continue
		}
		if p.updateECH(host, ech) {
			changed = append(changed, host)
		}
	}
	return changed
}

type healthStatus struct {
	Key        string `json:"key"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Fails      int    `json:"fails"`
	NextRetest int64  `json:"next_retest_unix"`
	Pin        bool   `json:"pin,omitempty"`
}

// Every entry on both axes, not only the burned ones: the panel builds its lists from this.
func (p *wsPool) healthRows() []healthStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	rows := make([]healthStatus, 0, len(p.ips)+len(p.snis))
	for _, ip := range p.ips {
		hs := healthStatus{Key: ip, Kind: "ip", State: "healthy", Pin: ip == p.pinIP}
		if r := p.ipHealth.rec(ip); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		rows = append(rows, hs)
	}
	for _, e := range p.snis {
		hs := healthStatus{Key: e.host, Kind: "sni", State: "healthy", Pin: e.host == p.pinSNI}
		if r := p.sniHealth.rec(e.host); r != nil {
			hs.State, hs.Fails, hs.NextRetest = r.state, r.fails, r.nextRetest
		}
		rows = append(rows, hs)
	}
	return rows
}

// The cursor follows the pin, so current() keeps answering with it once the pin is gone.
func (p *wsPool) stepToCurrentLocked() {
	ip, sni, ok := p.currentLocked()
	if !ok {
		return
	}
	for i, v := range p.ips {
		if v == ip {
			p.i = i
		}
	}
	for j, v := range p.snis {
		if v.host == sni.host {
			p.j = j
		}
	}
}

// The pair a verdict speaks about on an edge pool: the SNI is the digit a fail condemns.
type edgePair struct{ p *wsPool }

func (e edgePair) kinds() (string, string) { return "ip", "sni" }

func (e edgePair) live() (low, high string) {
	ip, sni, ok := e.p.current()
	if !ok {
		return "", ""
	}
	return ip, sni.host
}

func (e edgePair) keepCursorOn(low, high string) { e.p.keepCursorOn(low, high) }

func (e edgePair) clear(kind, key string) bool {
	return key != "" && e.p.clearBurn(kind, key)
}

func (e edgePair) burn(kind, key, reason string) {
	if key != "" {
		e.p.markSuspect(kind, key, reason)
	}
}

func (e edgePair) pick(kind, key string) bool {
	return key != "" && e.p.selectEntry(kind, key)
}

func (e edgePair) retest(kind, key string) bool {
	return key != "" && e.p.retestNow(kind, key)
}
