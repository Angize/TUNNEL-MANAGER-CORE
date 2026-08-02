package packet

import "time"

// Operational self-heal / pool-health timing knobs, package-level vars so the panel can tune fleet-wide
// behaviour via the core config. Mutable package state is safe here: one tnl-core process serves exactly
// ONE tunnel and ApplyTuning runs once at startup, before any carrier or pool is built. A zero/empty
// config value leaves the default untouched. Category 1 below — the pool health FSM, shared by both pools:
var (
	// suspectBackoff is the retest schedule (seconds) for a SUSPECT pool entry: it enters suspect
	// scheduled +[0] out, and each FAILED retest walks one step further down the list. Running off
	// the end (the last failed retest) drops the entry to DEAD.
	suspectBackoff = []int64{30, 60, 120, 300, 600}
	// deadRetest is the slow interval (seconds) a DEAD entry is retested on.
	deadRetest int64 = 1800
	// pinTTL bounds how long a manual pin keeps FORCING a not-yet-connected edge; it only matters for
	// a DEAD pinned edge (a healthy pin lands within one handshake and clears itself). Kept short so a
	// bad manual pick self-releases fast, while still outlasting a real handshake.
	pinTTL int64 = 30
	// dataFailThreshold: consecutive short-lived sessions on an IP before it is suspected.
	dataFailThreshold = 2
	// dataGoodWindow (sec): only blame an edge for a short session if SOME edge sustained a session
	// this recently — so a whole-server/local outage (every edge dies fast) never burns the pool.
	dataGoodWindow int64 = 120
)

// Category 2 — dead-detection / self-heal windows (derived from the per-tunnel keepalive):
var (
	// idleFor (ws/tcp read deadline) = idleMult × keepalive, floored at idleMinSecs seconds.
	idleMult    int64 = 4
	idleMinSecs int64 = 60
	// sessionStale (udp/raw/flux re-handshake) = sessionStaleMult × keepalive, floored at
	// sessionStaleMinSecs seconds.
	sessionStaleMult    int64 = 3
	sessionStaleMinSecs int64 = 10
	// pingLossThreshold closes a CLIENT connection after this many consecutive unanswered keepalives.
	// int32 so it compares directly against the atomic.Int32 unanswered-ping counter.
	pingLossThreshold int32 = 3
	// minLiveness (pool client) is the shortest a carrier may live and still count as a healthy
	// session; a handshake-then-quick-death is charged to the edge as a data-plane fault instead.
	minLiveness = 20 * time.Second
	// probeTimeout bounds a single differential/retest edge probe (TCP dial + TLS, no WS, no data).
	probeTimeout = 5 * time.Second
)

// (There is no category 3. The flux epoch length is NOT tunable through this file — it is a per-tunnel
// config field the panel always sends, and its last-resort fallback is a const in flux.go. It used to sit
// here as a var, which read as a knob ApplyTuning could set: there has never been a TuningInput field for
// it, so nothing could ever set it.)

// TuningInput mirrors the config's `tuning` object but lives in this package (no import cycle). main
// builds it from the loaded config and calls ApplyTuning ONCE at startup, before building carriers.
type TuningInput struct {
	SuspectBackoff      []int64
	DeadRetestSecs      int64
	PinTTLSecs          int64
	DataFailThreshold   int
	DataGoodWindowSecs  int64
	IdleMult            int64
	IdleMinSecs         int64
	SessionStaleMult    int64
	SessionStaleMinSecs int64
	PingLossThreshold   int
	MinLivenessSecs     int64
	ProbeTimeoutSecs    int64
}

// ApplyTuning overrides each operational default with its non-zero, in-range config value. A zero
// (or empty slice) leaves the compiled-in default. Every value is clamped to a sane range so a bad
// setting can slow or speed self-heal but can never wedge the core (e.g. a 0 that busy-loops). Call
// once at startup, before any carrier or pool is constructed.
func ApplyTuning(t TuningInput) {
	if len(t.SuspectBackoff) > 0 {
		bs := make([]int64, 0, len(t.SuspectBackoff))
		for _, v := range t.SuspectBackoff {
			if v >= 1 && v <= 86400 {
				bs = append(bs, v)
			}
		}
		if len(bs) > 0 {
			suspectBackoff = bs
		}
	}
	if t.DeadRetestSecs > 0 {
		deadRetest = tclamp(t.DeadRetestSecs, 5, 86400)
	}
	if t.PinTTLSecs > 0 {
		pinTTL = tclamp(t.PinTTLSecs, 1, 3600)
	}
	if t.DataFailThreshold > 0 {
		dataFailThreshold = tclamp(t.DataFailThreshold, 1, 100)
	}
	if t.DataGoodWindowSecs > 0 {
		dataGoodWindow = tclamp(t.DataGoodWindowSecs, 1, 86400)
	}
	if t.IdleMult > 0 {
		idleMult = tclamp(t.IdleMult, 1, 100)
	}
	if t.IdleMinSecs > 0 {
		idleMinSecs = tclamp(t.IdleMinSecs, 1, 86400)
	}
	if t.SessionStaleMult > 0 {
		sessionStaleMult = tclamp(t.SessionStaleMult, 1, 100)
	}
	if t.SessionStaleMinSecs > 0 {
		sessionStaleMinSecs = tclamp(t.SessionStaleMinSecs, 1, 86400)
	}
	if t.PingLossThreshold > 0 {
		pingLossThreshold = int32(tclamp(t.PingLossThreshold, 1, 100))
	}
	if t.MinLivenessSecs > 0 {
		minLiveness = time.Duration(tclamp(t.MinLivenessSecs, 1, 3600)) * time.Second
	}
	if t.ProbeTimeoutSecs > 0 {
		probeTimeout = time.Duration(tclamp(t.ProbeTimeoutSecs, 1, 120)) * time.Second
	}
}

// suspectStepAt returns the i-th suspect backoff step AND the index it actually used, clamped to the
// LAST element when the config-tunable schedule is shorter than i+1, so a short custom suspect_backoff
// cannot index out of range. It returns the INDEX because a caller entering the FSM at a fixed step must
// stamp healthRec.fails with that same index — retestBackoff does fails++ and then reads the schedule.
func suspectStepAt(i int) (int, int64) {
	if n := len(suspectBackoff); i >= n {
		i = n - 1
	}
	if i < 0 {
		i = 0
	}
	return i, suspectBackoff[i]
}

// tclamp clamps v to [lo, hi]. One generic over the integer widths the tuning knobs use (was two
// byte-identical copies, tclamp64 for int64 fields and tclampInt for the two int ones).
func tclamp[T int | int32 | int64](v, lo, hi T) T {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
