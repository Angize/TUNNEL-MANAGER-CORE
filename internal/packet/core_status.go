package packet

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// coreStatus is a lightweight status-file writer + event ring for the connectionless datagram transports
// (udp / raw / flux). They have no ws edge pool, but a client still wants PRECISE, core-observed events
// in the node/panel log. It writes the SAME status JSON shape the ws pool does, minus the pool-only
// fields, so the node's reader consumes it unchanged. Client-only; the nil receiver no-ops elsewhere.
type coreStatus struct {
	mu      sync.Mutex
	writeMu sync.Mutex // serializes the file write+rename so concurrent writers don't race the shared .tmp path
	path    string
	active  string // short human descriptor of the live carrier, e.g. "udp · 1.2.3.4:443"
	events  []coreEvent
	evSeq   int64
	wasDown bool  // a disconnect is pending a matching recovery -> the next connect is a reconnect
	hb      int64 // unix-seconds of the last authenticated inbound frame (lastRx); a periodic liveness heartbeat
	dw      int64 // this carrier's RESOLVED dead-window in seconds — the single number a reader uses to age hb
	// role tells a reader which end wrote this. A SERVER legitimately sits with hb==0 until a client
	// first reaches it — that is "waiting", not "died" — and only the writer knows which it is.
	role string
}

// hbInterval is the CEILING on how often a client carrier republishes its lastRx heartbeat into the
// status file, so a reader can tell a live-but-idle tunnel (hb advances every keepalive) from a dead one
// (hb frozen) with no ICMP. Kept small relative to keepalive so the freeze becomes visible promptly.
const hbInterval = 5 * time.Second

// hbMinInterval floors the republish period: a very tight dead-window must not turn every tunnel's
// heartbeat into a sub-second status-file rewrite loop.
const hbMinInterval = time.Second

// hbPeriod resolves how often to republish for a carrier whose resolved dead-window is dwSecs — the same
// number setDW publishes and a reader ages hb against. hb is a TIMESTAMP, not a tick, so a late
// republish INFLATES the age by up to one whole period: a fixed 5s is fine against a 30s window and
// wrong against a tight one. dw/4 leaves about a tenth of the window as margin; dwSecs<=0 keeps the ceiling.
func hbPeriod(dwSecs int64) time.Duration {
	p := hbInterval
	if dwSecs > 0 {
		if quarter := time.Duration(dwSecs) * time.Second / 4; quarter < p {
			p = quarter
		}
	}
	if p < hbMinInterval {
		p = hbMinInterval
	}
	return p
}

// heartbeatLoop republishes the carrier's lastRx (unix-seconds) via beat every period until done closes:
// an immediate publish so a reader sees a heartbeat at startup, then one per tick.
func heartbeatLoop(beat func(int64), lastRx *atomic.Int64, done <-chan struct{}, period time.Duration) {
	beat(lastRx.Load() / int64(time.Second))
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			beat(lastRx.Load() / int64(time.Second))
		}
	}
}

// heartbeat republishes lastRx into the coreStatus file, paced against the carrier's dead-window dwSecs.
// A nil status writer (no status_path wired) is a no-op, so it is always safe to start for any client.
// The nil guard stays HERE so a nil status never leaves a goroutine ticking forever.
func heartbeat(s *coreStatus, lastRx *atomic.Int64, done <-chan struct{}, dwSecs int64) {
	if s == nil {
		return
	}
	heartbeatLoop(s.beat, lastRx, done, hbPeriod(dwSecs))
}

// heartbeatPool is heartbeat for a ws/http edge pool, whose status file is written by wsPool.writeStatus
// (not coreStatus), so an idle pooled tunnel reads live, not half-open. A nil pool is a no-op.
func heartbeatPool(p *wsPool, lastRx *atomic.Int64, done <-chan struct{}, dwSecs int64) {
	if p == nil {
		return
	}
	heartbeatLoop(p.beat, lastRx, done, hbPeriod(dwSecs))
}

// beat records the latest lastRx (unix-seconds) and flushes the file. lastRx only moves forward (it is
// re-baselined to now on a re-handshake / rotation), so hb is monotonic in practice.
func (s *coreStatus) beat(sec int64) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.hb = sec
	s.mu.Unlock()
	s.write()
}

// setDW publishes this carrier's resolved dead-window (seconds) so a reader ages hb against the SAME
// number the core self-heals on, instead of re-deriving a private multiplier. Called once at Run.
func (s *coreStatus) setDW(secs int64) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.dw = secs
	s.mu.Unlock()
	s.write()
}

// roleOf names the end that writes a status file, so a reader can tell a server WAITING for its first
// client (hb still 0, perfectly normal) from a client that was answered and then went quiet.
func roleOf(isClient bool) string {
	if isClient {
		return "client"
	}
	return "server"
}

// newCoreStatus creates the writer and flushes an initial (empty-ring) file so a reader sees a live
// tunnel immediately rather than a missing file.
func newCoreStatus(path, active, role string) *coreStatus {
	s := &coreStatus{path: path, active: active, role: role}
	s.write()
	adoptCfgWarnSink(func(code, detail string) { s.event("cfg", code, detail) })
	return s
}

// cfgWarns carries a startup CONFIGURATION warning — a setting the operator chose that the host did not
// actually grant — from wherever it is discovered to the status file the panel reads. A journal line
// reaches nobody: the node reads the core's journal only on the failure branch after a build, so a core
// that STARTED and merely had its buffers clamped said nothing. A note raised before the sink exists waits.
var cfgWarns struct {
	mu      sync.Mutex
	pending []cfgWarnNote
	sink    func(code, detail string)
}

type cfgWarnNote struct{ code, detail string }

// noteCfgWarn records one configuration warning for the panel. detail is DATA, never prose: the panel
// owns the Persian (the same split the node/panel event protocol uses everywhere else).
func noteCfgWarn(code, detail string) {
	cfgWarns.mu.Lock()
	defer cfgWarns.mu.Unlock()
	if cfgWarns.sink != nil {
		cfgWarns.sink(code, detail)
		return
	}
	cfgWarns.pending = append(cfgWarns.pending, cfgWarnNote{code: code, detail: detail})
}

// adoptCfgWarnSink installs the status-file sink and flushes everything raised before it existed.
func adoptCfgWarnSink(f func(code, detail string)) {
	cfgWarns.mu.Lock()
	pending := cfgWarns.pending
	cfgWarns.pending, cfgWarns.sink = nil, f
	cfgWarns.mu.Unlock()
	for _, n := range pending {
		f(n.code, n.detail)
	}
}

// event appends one event to the ring (newest kept, capped at coreEventRing) and flushes the file.
func (s *coreStatus) event(kind, code, detail string) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.evSeq++
	s.events = append(s.events, coreEvent{Seq: s.evSeq, TS: time.Now().Unix(), Kind: kind, Code: code, Detail: detail})
	if len(s.events) > coreEventRing {
		s.events = s.events[len(s.events)-coreEventRing:]
	}
	s.mu.Unlock()
	s.write()
}

// down records a disconnect / self-heal trigger with a precise reason and arms the next successful
// connect to be reported as a recovery.
func (s *coreStatus) down(code, detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.wasDown = true
	s.mu.Unlock()
	s.event("down", code, detail)
}

// reconnected records a recovery — but ONLY if a disconnect is pending, so the initial connect at
// startup is never mislabelled as a self-heal.
func (s *coreStatus) reconnected(detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	pending := s.wasDown
	s.wasDown = false
	s.mu.Unlock()
	if pending {
		s.event("up", "reconnect", detail)
	}
}

// setActive refreshes the live-carrier descriptor (e.g. "udp · 1.2.3.4:443") after a destination
// rotation so the status file's "active" field doesn't go stale. Locks only to swap the field, then
// flushes outside s.mu because write() re-locks mu.
func (s *coreStatus) setActive(a string) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	s.active = a
	s.mu.Unlock()
	s.write()
}

func (s *coreStatus) write() {
	if s == nil || s.path == "" {
		return
	}
	// Hold writeMu across BOTH the snapshot and the file write so the on-disk write order can never invert
	// the snapshot order — an older snapshot must never clobber a newer status file. Lock order is
	// writeMu->mu (mu released before I/O), matching ws_pool.go's writeStatus, so the two never deadlock.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	evs := append([]coreEvent(nil), s.events...) // copy so the marshal runs outside s.mu
	active := s.active
	hb := s.hb
	dw := s.dw
	role := s.role
	s.mu.Unlock()
	payload := struct {
		Active string      `json:"active"`
		Events []coreEvent `json:"events"`
		HB     int64       `json:"hb"`
		DW     int64       `json:"dw"`
		Role   string      `json:"role"`
		TS     int64       `json:"ts"`
	}{Active: active, Events: evs, HB: hb, DW: dw, Role: role, TS: time.Now().Unix()}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	writeFileAtomic(s.path, buf, 0o600)
}

// writeFileAtomic writes data to path via a .tmp file + rename, so a reader never sees a half-written
// status file. The single durability primitive shared by all three status writers (coreStatus / peerPool
// / wsPool); each passes its own perm.
func writeFileAtomic(path string, data []byte, perm os.FileMode) {
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, perm) == nil {
		_ = os.Rename(tmp, path)
	}
}

// staleSince reports whether last (unix-nano of the last inbound frame) has aged past window. A zero last
// means "no baseline yet" -> not stale.
func staleSince(last int64, window time.Duration) bool {
	return last != 0 && time.Since(time.Unix(0, last)) > window
}
