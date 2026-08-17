package packet

import (
	"encoding/json"
	"os"
	"sync"
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
	wasDown bool // a disconnect is pending a matching recovery -> the next connect is a reconnect
	// tracker is the epoch a liveness verdict is keyed on. Sampled on every write, so any mover that
	// publishes its status — which is all of the deliberate ones — moves the epoch by doing so.
	tracker pathTracker
}

// trackPath installs the carrier's live-path report and starts the sampler that catches a mover which
// publishes nothing. Client-only; a carrier with no tuple to name (dns) simply never calls it.
func (s *coreStatus) trackPath(live func() (pathKey, bool), closeCh <-chan struct{}) {
	if s == nil {
		return
	}
	s.tracker.setLive(live)
	go samplePathLoop(&s.tracker, s.write, closeCh)
}

// pathEpoch is the epoch a verdict must carry to be acted on. Nil-safe, and zero until a path has
// been observed — which is also when there is nothing to judge.
func (s *coreStatus) pathEpoch() int64 {
	if s == nil {
		return 0
	}
	e, _, _ := s.tracker.snapshot()
	return e
}

// verdictPath is the file the node's tun probe drops its verdict about THIS TUNNEL into. Derived from
// the status file both ends already agree on, like the .echcmd sidecar, so no config key carries it.
//
// It belongs to the tunnel and not to a pool because the question it answers — does this path carry —
// is about the tunnel. A client with no pool still has a path, still has free rungs to spend on it,
// and used to have no way to be told anything at all. Empty when no status file is wired: then there
// is no judge.
func (s *coreStatus) verdictPath() string {
	if s == nil || s.path == "" {
		return ""
	}
	return s.path + ".verdict"
}

// newCoreStatus creates the writer and flushes an initial (empty-ring) file so a reader sees a live
// tunnel immediately rather than a missing file.
func newCoreStatus(path, active string) *coreStatus {
	s := &coreStatus{path: path, active: active}
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
	s.tracker.sample() // before any lock: the tracker has its own, and livePath reads only carrier atomics
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	evs := append([]coreEvent(nil), s.events...) // copy so the marshal runs outside s.mu
	active := s.active
	s.mu.Unlock()
	epoch, path, ready := s.tracker.snapshot()
	payload := struct {
		Active string      `json:"active"`
		Epoch  int64       `json:"epoch"`
		Ready  bool        `json:"ready"`
		Path   pathKey     `json:"path"`
		Events []coreEvent `json:"events"`
		TS     int64       `json:"ts"`
	}{Active: active, Epoch: epoch, Ready: ready, Path: path, Events: evs, TS: time.Now().Unix()}
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
	// Both errors are REPORTED. Swallowing them made a full or read-only filesystem look like a dead
	// tunnel: the status file freezes at its last good contents, the node's reader keeps parsing it, and
	// the dashboard goes red pointing at the peer. Throttled, because a full disk fails every write.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		statusWriteLog.note("core/status: writing "+tmp, err)
		_ = os.Remove(tmp) // a partial temp file is of no use to anyone
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		// The target still holds the last good snapshot, which is what readers use, so the temp carries
		// nothing they need -- drop it instead of leaving one stale file per failed write.
		statusWriteLog.note("core/status: replacing "+path, err)
		_ = os.Remove(tmp)
	}
}

// statusWriteLog throttles the status-file write errors: one line per sendErrEvery, shared by all three
// writers, so a filesystem that fails every write names itself once instead of per snapshot.
var statusWriteLog sendErrLog

// staleSince reports whether last (unix-nano of the last inbound frame) has aged past window. A zero last
// means "no baseline yet" -> not stale.
func staleSince(last int64, window time.Duration) bool {
	return last != 0 && time.Since(time.Unix(0, last)) > window
}
