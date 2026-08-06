package packet

// healthSet is the burn/retest bookkeeping for ONE axis of a rotation pool: which of its entries are
// sidelined, how far down the backoff each one is, and when it may be tried again. An entry absent from
// the map is healthy — only suspect and dead entries are ever tracked.
//
// It is deliberately NOT self-synchronised. Both pools take a decision and publish it under one hold of
// their own mutex ("is anything eligible, and if not what is the least-bad") and splitting that across a
// second lock would let the answer change between the two halves. So every method here is a
// caller-holds-the-lock method, exactly like the *Locked methods it replaces.
//
// The direct pool has one of these; the CDN edge pool has two, one per axis. That is the whole
// difference between them at this layer, and the reason the FSM had been written out three times.
type healthSet struct {
	recs map[string]*healthRec
	// now reads the OWNER's clock through a trampoline rather than copying it. Tests replace the pool's
	// `now` field after construction; a captured copy would leave every entry here ageing against the
	// real wall clock while the pool aged against the fake one, and the whole ladder would silently
	// stop being tested.
	now func() int64
}

// newHealthSet takes a pointer to the owner's clock field, so a later swap of that field is seen here.
func newHealthSet(clock *func() int64) healthSet {
	return healthSet{recs: map[string]*healthRec{}, now: func() int64 { return (*clock)() }}
}

// rec returns the entry's record, or nil when it is healthy.
func (h healthSet) rec(key string) *healthRec { return h.recs[key] }

// healthy reports whether the entry carries no record at all.
func (h healthSet) healthy(key string) bool { return h.recs[key] == nil }

// due reports whether the entry is tracked AND its backoff has elapsed — the "may be tried again now"
// test. A healthy entry is not due; it was never sidelined.
func (h healthSet) due(key string) bool {
	r := h.recs[key]
	return r != nil && r.nextRetest <= h.now()
}

// eligible is healthy-or-due: what the rotation could actually pick this instant. It is what "a full lap"
// has to be counted against — a condemned entry cannot be tried, so counting the raw list declares laps
// that never happened.
func (h healthSet) eligible(key string) bool {
	r := h.recs[key]
	return r == nil || r.nextRetest <= h.now()
}

// tier ranks an entry for the least-bad fallback: 0 healthy, 1 suspect, 2 dead, with nextRetest as the
// tiebreak inside a tier.
func (h healthSet) tier(key string) (tier int, next int64) {
	r := h.recs[key]
	if r == nil {
		return 0, 0
	}
	if r.state == stateDead {
		return 2, r.nextRetest
	}
	return 1, r.nextRetest
}

// best returns the least-bad of `keys` by tier. Callers pass a non-empty list; an empty one yields "".
func (h healthSet) best(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	best := keys[0]
	bt, bn := h.tier(best)
	for _, k := range keys[1:] {
		if t, n := h.tier(k); t < bt || (t == bt && n < bn) {
			best, bt, bn = k, t, n
		}
	}
	return best
}

// sideline puts a HEALTHY entry into suspect at the first backoff step, and does NOTHING to one that is
// already tracked: from the first burn on, the retest scheduler owns that entry's cadence, and a second
// live failure arriving while it waits must not push it further down a ladder it is already on.
// Reports whether the entry was fresh — the transition callers log, since repeats are not news.
func (h healthSet) sideline(key string) (fresh bool) {
	if h.recs[key] != nil {
		return false
	}
	h.recs[key] = &healthRec{state: stateSuspect, nextRetest: h.now() + suspectBackoff[0]}
	return true
}

// burn is sideline plus a LADDER STEP for an entry already tracked: each live failure on the same entry
// costs it another step toward dead. The direct pool wants this — its burn comes from the carrier's own
// rotation, one per failover round, so stepping is the ladder working as intended. Keep the two apart:
// collapsing them makes repeated verdicts on one entry race it to dead, or leaves a genuinely dying
// endpoint stuck one step from healthy forever.
func (h healthSet) burn(key string) (fresh bool) {
	if h.sideline(key) {
		return true
	}
	retestBackoff(h.recs[key], h.now())
	return false
}

// retestFailed reschedules a tracked entry after a failed retest. Same schedule as a live failure — the
// FSM does not care which of the two discovered the entry is still down.
func (h healthSet) retestFailed(r *healthRec) { retestBackoff(r, h.now()) }

// clear drops the entry's record outright, so a proven-carrying entry is healthy again immediately
// instead of waiting out its ladder. Reports whether anything was actually cleared.
func (h healthSet) clear(key string) bool {
	_, had := h.recs[key]
	delete(h.recs, key)
	return had
}

// probeAllNow pulls EVERY tracked entry's retest forward to now, so the rotation may select them again at
// once instead of waiting out the backoff — and the tun probe then judges them.
func (h healthSet) probeAllNow() {
	now := h.now()
	for _, r := range h.recs {
		r.nextRetest = now
	}
}

// countEligible is eligible() over a whole list, which is how a lap is sized.
func (h healthSet) countEligible(keys []string) int {
	n := 0
	for _, k := range keys {
		if h.eligible(k) {
			n++
		}
	}
	return n
}
