package packet

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"
)

type coreStatus struct {
	mu        sync.Mutex
	writeMu   sync.Mutex
	path      string
	active    string
	events    []coreEvent
	evSeq     int64
	wasDown   bool
	rollTries int

	// What the pools publish through this one file. Registered once at startup; read on every write.
	health []func() []healthStatus
	pair   func() (low, high, lowKind, highKind string)

	tracker pathTracker
}

// A pool joins the tunnel's one status file instead of writing a second one.
func (s *coreStatus) addHealth(rows func() []healthStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.health = append(s.health, rows)
	s.mu.Unlock()
	s.write()
}

// The live pair, in machine form. The `active` string beside it is a display label and has always been
// parsed by eye; a verdict may not rest on that.
func (s *coreStatus) setPair(live func() (low, high, lowKind, highKind string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.pair = live
	s.mu.Unlock()
	s.write()
}

func (s *coreStatus) trackPath(live func() (pathKey, bool), closeCh <-chan struct{}) {
	if s == nil {
		return
	}
	s.tracker.setLive(live)
	go samplePathLoop(&s.tracker, s.write, closeCh)
}

// The carrier has established a session. Called BEFORE anything publishes the new pair, so the first
// status file carrying it also carries the epoch that goes with it -- see pathTracker.freshen.
func (s *coreStatus) newSession() {
	if s == nil {
		return
	}
	s.tracker.freshen()
}

func (s *coreStatus) pathEpoch() int64 {
	if s == nil {
		return 0
	}
	e, _, _ := s.tracker.snapshot()
	return e
}

func (s *coreStatus) verdictPath() string { return s.sidecar(".verdict") }

// The operator's mailbox: pins and per-entry retests. Separate from the verdict's, because two writers
// on one path means os.replace can drop whichever arrived first.
func (s *coreStatus) pinPath() string { return s.sidecar(".pin") }

func (s *coreStatus) echCmdPath() string { return s.sidecar(".echcmd") }

func (s *coreStatus) sidecar(suffix string) string {
	if s == nil || s.path == "" {
		return ""
	}
	return s.path + suffix
}

func newCoreStatus(path, active string) *coreStatus {
	s := &coreStatus{path: path, active: active}
	s.write()
	adoptCfgWarnSink(func(code, detail string) { s.event("cfg", code, detail) })
	return s
}

var cfgWarns struct {
	mu      sync.Mutex
	pending []cfgWarnNote
	sink    func(code, detail string)
}

type cfgWarnNote struct{ code, detail string }

func noteCfgWarn(code, detail string) {
	cfgWarns.mu.Lock()
	defer cfgWarns.mu.Unlock()
	if cfgWarns.sink != nil {
		cfgWarns.sink(code, detail)
		return
	}
	cfgWarns.pending = append(cfgWarns.pending, cfgWarnNote{code: code, detail: detail})
}

func adoptCfgWarnSink(f func(code, detail string)) {
	cfgWarns.mu.Lock()
	pending := cfgWarns.pending
	cfgWarns.pending, cfgWarns.sink = nil, f
	cfgWarns.mu.Unlock()
	for _, n := range pending {
		f(n.code, n.detail)
	}
}

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

func (s *coreStatus) down(code, detail string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.wasDown = true
	s.mu.Unlock()
	s.event("down", code, detail)
}

// One rotation the operator did not ask for. A proactive step is a scheduled move; a failover follows
// a fault, so it also arms the "up" that will report the recovery.
func (s *coreStatus) rotated(axis, detail string, proactive bool) {
	if proactive {
		s.event("down", axis+"-rotate", detail)
		return
	}
	s.down(axis+"-rotate", detail)
}

// A source-port redraw is only worth a line if it WORKED, and then only for the port that worked. The
// rung draws one on every verdict for as long as the outage lasts, so the draw is only remembered
// here; carrying() and portClaimLost() are the two ways the claim ends.
func (s *coreStatus) portRedrawn() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.rollTries++
	s.mu.Unlock()
}

// The node's probe found traffic crossing. The ONLY place a source-port redraw may be credited for a
// recovery: the draw sends a handshake of its own, and an answered handshake is exactly what a
// filtered path still gives while carrying nothing -- so the carrier's own reconnect announced every
// draw as a success while the ladder climbed straight past it, twice per outage.
func (s *coreStatus) carrying() {
	if s == nil {
		return
	}
	s.mu.Lock()
	tries := s.rollTries
	s.rollTries = 0
	s.mu.Unlock()
	if tries == 0 {
		return
	}
	// Sampled, not read: a draw changes the port without publishing anything, so the last snapshot can
	// still be holding the port the tunnel LEFT.
	s.tracker.sample()
	if _, path, _ := s.tracker.snapshot(); path.Sport != 0 {
		s.event("down", "port-roll",
			"sport:"+strconv.Itoa(int(path.Sport))+" tries:"+strconv.Itoa(tries))
	}
}

// The ladder climbed past the source port. Whatever brings the tunnel back now is the handshake's
// doing or the walk's, and crediting the port for it would be a guess.
func (s *coreStatus) portClaimLost() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.rollTries = 0
	s.mu.Unlock()
}

// The carrier has a session again. A fact about the CARRIER, not about the path -- see carrying().
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

	s.tracker.sample()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	evs := append([]coreEvent(nil), s.events...)
	active := s.active
	sources := append([]func() []healthStatus(nil), s.health...)
	livePair := s.pair
	s.mu.Unlock()

	// Outside s.mu: these reach into the pools' own locks, and the pools call back in here to flush.
	health := []healthStatus{}
	for _, rows := range sources {
		health = append(health, rows()...)
	}
	var pair pairStatus
	if livePair != nil {
		pair.Low, pair.High, pair.LowKind, pair.HighKind = livePair()
	}

	epoch, path, ready := s.tracker.snapshot()
	payload := struct {
		Active string         `json:"active"`
		Epoch  int64          `json:"epoch"`
		Ready  bool           `json:"ready"`
		Path   pathKey        `json:"path"`
		Pair   pairStatus     `json:"pair"`
		Health []healthStatus `json:"health"`
		Events []coreEvent    `json:"events"`
		TS     int64          `json:"ts"`
	}{Active: active, Epoch: epoch, Ready: ready, Path: path, Pair: pair, Health: health,
		Events: evs, TS: time.Now().Unix()}
	buf, err := json.Marshal(payload)
	if err != nil {
		return
	}
	writeFileAtomic(s.path, buf, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) {

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		statusWriteLog.note("core/status: writing "+tmp, err)
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {

		statusWriteLog.note("core/status: replacing "+path, err)
		_ = os.Remove(tmp)
	}
}

var statusWriteLog sendErrLog

type pairStatus struct {
	Low      string `json:"low"`
	High     string `json:"high"`
	LowKind  string `json:"low_kind"`
	HighKind string `json:"high_kind"`
}
