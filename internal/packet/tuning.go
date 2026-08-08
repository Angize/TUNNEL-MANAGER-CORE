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
	suspectBackoff = []int64{600, 1800, 3600}
	// deadRetest is the slow interval (seconds) a DEAD entry is retested on.
	deadRetest int64 = 21600
)

// Category 2 — dead-detection / self-heal windows (derived from the per-tunnel keepalive):
var (
	// Both windows are a MULTIPLE of the tunnel's own keepalive and nothing else, so raising or lowering
	// keepalive moves them with it. They used to carry a seconds FLOOR as well, which meant the ws/tcp
	// window sat at 60 s for every keepalive at or under 15 and the knob beside it did nothing.
	//
	// The multiplier may not go below 2. keepaliveInterval is clamped to [0.6,1.3]×keepalive, so the
	// longest real gap between two pings is 1.3×; a window at 1× would expire BETWEEN pings and tear
	// down a healthy idle carrier. 2× is the same floor deadWindow already applies to an explicit
	// dead_after_secs.
	deadMult int64 = 3
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
	SuspectBackoff    []int64
	DeadRetestSecs    int64
	DeadMult          int64
	PingLossThreshold int
	MinLivenessSecs   int64
	ProbeTimeoutSecs  int64
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
	if t.DeadMult > 0 {
		deadMult = tclamp(t.DeadMult, 2, 100)
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
