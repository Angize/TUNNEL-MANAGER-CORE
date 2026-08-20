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

	if p.chosen != "" {
		ip := p.ips[p.i%len(p.ips)]
		sni := p.snis[p.j%len(p.snis)]
		if activeLabel(ip, sni.host) == p.chosen {
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

// Put the cursor back on a combination, the way the direct pool does after a warm dial it could not
// build. Compares the RAW cursor, not currentLocked(), which would resolve and step.
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

func (p *wsPool) stepLocked() {
	p.chosen = ""
	p.j++
	if p.j >= len(p.snis) {
		p.j = 0
		p.i++
		if p.i >= len(p.ips) {
			p.i = 0
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

func (p *wsPool) advanceIP() {
	p.mu.Lock()
	p.chosen = ""
	if len(p.ips) > 0 {
		p.i = (p.i + 1) % len(p.ips)
	}
	p.mu.Unlock()
}

func (p *wsPool) restoreSNIs() {
	p.mu.Lock()
	cleared := len(p.sniHealth.recs) > 0
	p.sniHealth = newHealthSet(&p.now)
	p.mu.Unlock()
	if cleared {
		p.publish()
	}
}

func (p *wsPool) activeIPIdx() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.i
}

func (p *wsPool) burnCount() uint64 { return p.burns.Load() }

type wsSNIs struct{ p *wsPool }

func (a wsSNIs) eligibleCount() int { return a.p.eligibleSNIs() }
func (a wsSNIs) burnCount() uint64  { return a.p.burnCount() }
func (a wsSNIs) restoreAll()        { a.p.restoreSNIs() }

type wsEdges struct{ p *wsPool }

func (a wsEdges) activeIdx() int { return a.p.activeIPIdx() }

func (p *wsPool) snisCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.snis)
}

func (p *wsPool) comboCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ips) * len(p.snis)
}

func (p *wsPool) eligibleSNIs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	keys := make([]string, len(p.snis))
	for i, e := range p.snis {
		keys[i] = e.host
	}
	return p.sniHealth.countEligible(keys)
}

func (p *wsPool) markSuspect(kind, key, reason string) {
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

func (p *wsPool) restorePinTookLocked() {
	for k, rec := range p.pinTook {
		if rec == nil {
			continue
		}
		if kind, key, found := strings.Cut(k, ":"); found {
			p.healthMap(kind).recs[key] = rec
		}
	}
	clear(p.pinTook)
}

func (p *wsPool) restorePinTookAxisLocked(kind, key string) {
	live := p.pinIP
	if kind == "sni" {
		live = p.pinSNI
	}
	if live == "" || live == key {
		return
	}
	k := kind + ":" + live
	if rec := p.pinTook[k]; rec != nil {
		p.healthMap(kind).recs[live] = rec
	}
	delete(p.pinTook, k)
}

// One way a pin ends here too. `matched` runs under the lock and may count.
func (p *wsPool) dropPin(reason string, matched func() bool) bool {
	p.mu.Lock()
	hit := matched()
	if hit {
		p.restorePinTookLocked()
		p.pinIP, p.pinSNI = "", ""
	}
	p.mu.Unlock()
	if hit {
		p.publish()
		p.event("pool", "pin_dropped", "edge:"+reason)
	}
	return hit
}

// The operator's pick could not be reached. One refused dial is the whole answer -- waiting for a second
// only delays the burn that is coming anyway, and forces traffic onto an edge that will not open.
func (p *wsPool) pinCannotLand(ip, host string) bool {
	return p.dropPin("cannot-land", func() bool {
		return (p.pinIP != "" && p.pinIP == ip) || (p.pinSNI != "" && p.pinSNI == host)
	})
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
	p.chosen = ""
	ok := false
	if p.pinTook == nil {
		p.pinTook = map[string]*healthRec{}
	}

	p.restorePinTookAxisLocked(kind, key)
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
		p.stepToCurrentLocked()
	}
	p.mu.Unlock()
	if ok {
		p.publish()
		if kind == "ip" {

			p.reassessRotation()
		}
	}
	return ok
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

func (e edgePair) kinds() (string, string) { return "sni", "ip" }

func (e edgePair) live() (low, high string) {
	ip, sni, ok := e.p.current()
	if !ok {
		return "", ""
	}
	return sni.host, ip
}

func (e edgePair) keepCursorOn(low, high string) { e.p.keepCursorOn(high, low) }

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
