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

type WSPoolSNI struct {
	Host string
	ECH  string
	Path string
}

func DialWSPoolCfg(dev *tun.Device, obfs, cryptoOn bool, psk, cipher string, ips []string, snis []WSPoolSNI, rotate time.Duration, statusPath string, httpc bool, httpcMode string) (*TCP, error) {
	entries := make([]wsSNIEntry, 0, len(snis))
	for _, s := range snis {
		var ech []byte
		if s.ECH != "" {
			ech, _ = base64.StdEncoding.DecodeString(s.ECH)
		}
		entries = append(entries, wsSNIEntry{host: s.Host, ech: ech, path: s.Path})
	}
	pool := newWSPoolFromCfg(ips, entries, statusPath)
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
	writeMu     sync.Mutex
	ips         []string
	snis        []wsSNIEntry
	ipHealth    healthSet
	sniHealth   healthSet
	i, j        int
	statusPath  string
	active      string
	rotDegraded bool
	chosen      string
	events      []coreEvent
	evSeq       int64
	wasDown     bool
	pinIP       string
	pinSNI      string
	pinTries    int

	pinTook map[string]*healthRec
	now     func() int64

	tracker pathTracker
}

func (p *wsPool) trackPath(live func() (pathKey, bool), closeCh <-chan struct{}) {
	p.tracker.setLive(live)
	go samplePathLoop(&p.tracker, p.writeStatus, closeCh)
}

func (p *wsPool) pathEpoch() int64 {
	e, _, _ := p.tracker.snapshot()
	return e
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
	p.evSeq++
	p.events = append(p.events, coreEvent{Seq: p.evSeq, TS: time.Now().Unix(), Kind: kind, Code: code, Detail: detail})
	if len(p.events) > coreEventRing {
		p.events = p.events[len(p.events)-coreEventRing:]
	}
	p.mu.Unlock()
	p.writeStatus()
}

func (p *wsPool) down(code, detail string) {
	p.mu.Lock()
	p.wasDown = true
	p.mu.Unlock()
	p.event("down", code, detail)
}

func newWSPool(ips []string, snis []wsSNIEntry, statusPath string) *wsPool {
	p := &wsPool{ips: ips, snis: snis,
		statusPath: statusPath, now: func() int64 { return time.Now().Unix() }}
	p.ipHealth, p.sniHealth = newHealthSet(&p.now), newHealthSet(&p.now)
	p.writeStatus()
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

func (p *wsPool) setActive(combo string) {
	if combo == "" {
		return
	}
	p.mu.Lock()
	changed := p.active != combo
	p.active = combo
	pending := p.wasDown
	p.wasDown = false
	p.mu.Unlock()
	if pending {
		p.event("up", "reconnect", combo)
	} else if changed {
		p.writeStatus()
	}
}

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

func (p *wsPool) advanceEdgeFreshRow() {
	p.mu.Lock()
	p.chosen = ""
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
	p.chosen = ""
	if len(p.snis) > 0 {
		p.j = (p.j + 1) % len(p.snis)
	}
	p.mu.Unlock()
}

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
	fresh := p.healthMap(kind).burn(key)
	p.mu.Unlock()
	if fresh {
		p.event("burn", reason, kind+":"+key)
	}
	p.writeStatus()
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

func (p *wsPool) releasePin() {
	p.mu.Lock()
	changed := p.pinIP != "" || p.pinSNI != ""
	if changed {
		p.restorePinTookLocked()
	}
	p.pinIP, p.pinSNI = "", ""
	p.mu.Unlock()
	if changed {
		p.writeStatus()
		p.event("pool", "pin_dropped", "tun-probe")
	}
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

func (p *wsPool) retestResult(kind, key string, success bool) {
	p.mu.Lock()
	m := p.healthMap(kind)
	r := m.rec(key)
	if r == nil {
		p.mu.Unlock()
		return
	}
	if success {

		r.nextRetest = p.now()
	} else {
		m.retestFailed(r)
	}
	p.mu.Unlock()
	p.writeStatus()
	if kind == "ip" {
		p.reassessRotation()
	}
}

type retestSpec struct {
	kind string
	key  string
	ip   string
	sni  wsSNIEntry
}

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

func (p *wsPool) probeAllNow() {
	p.mu.Lock()
	p.ipHealth.probeAllNow()
	p.sniHealth.probeAllNow()
	p.mu.Unlock()
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
		p.pinTries = 0

		if ip, sni, got := p.currentLocked(); got {
			p.active = activeLabel(ip, sni.host)
		}
	}
	p.mu.Unlock()
	if ok {
		p.writeStatus()
		if kind == "ip" {

			p.reassessRotation()
		}
	}
	return ok
}

func (p *wsPool) pinApplied(ip, host string) {
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
	if changed {
		p.pinTries = 0
	}
	p.mu.Unlock()
	if changed {
		p.writeStatus()
	}
}

func (p *wsPool) cmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".cmd"
}

func (p *wsPool) readCmd() (c poolCmd, ok bool) {
	if c, ok = readPoolCmd(p.cmdPath()); !ok {
		return c, false
	}
	if c.Kind != "sni" {
		c.Kind = "ip"
	}
	return c, true
}

func (p *wsPool) activeCombo() (ip, sni string) {
	p.mu.Lock()
	a := p.active
	p.mu.Unlock()
	if i := strings.Index(a, activeSep); i >= 0 {
		return a[:i], a[i+len(activeSep):]
	}
	return a, ""
}

func (p *wsPool) clearBurn(kind, key string) bool {
	p.mu.Lock()
	had := p.healthMap(kind).clear(key)
	p.mu.Unlock()
	if had {
		p.writeStatus()

		if kind == "ip" {
			p.reassessRotation()
		}
	}
	return had
}

func (p *wsPool) echCmdPath() string {
	if p.statusPath == "" {
		return ""
	}
	return p.statusPath + ".echcmd"
}

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

type healthStatus struct {
	Key        string `json:"key"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Fails      int    `json:"fails"`
	NextRetest int64  `json:"next_retest_unix"`
}

func (p *wsPool) writeStatus() {
	if p.statusPath == "" {
		return
	}

	p.tracker.sample()
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
	evs := append([]coreEvent(nil), p.events...)
	epoch, path, ready := p.tracker.snapshot()
	st := struct {
		Active string         `json:"active"`
		Epoch  int64          `json:"epoch"`
		Ready  bool           `json:"ready"`
		Path   pathKey        `json:"path"`
		Health []healthStatus `json:"health"`
		Events []coreEvent    `json:"events"`
		TS     int64          `json:"ts"`
	}{Active: p.active, Epoch: epoch, Ready: ready, Path: path, Health: health, Events: evs, TS: time.Now().Unix()}
	p.mu.Unlock()
	if data, err := json.Marshal(st); err == nil {

		writeFileAtomic(p.statusPath, data, 0o644)
	}
}
