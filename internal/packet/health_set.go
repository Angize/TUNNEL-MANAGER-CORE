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

// burn is the live-failure verdict, and it is ONE rule for both pools, keyed on what the failure actually
// measured:
//
//   - fresh entry -> sidelined at the first backoff step.
//   - tracked and still WAITING out its backoff -> nothing. The scheduler owns its cadence, and a verdict
//     arriving during the wait measured a combination the rotation was not even trying.
//   - tracked and DUE -> a step. That entry had just been handed the live retry its ladder granted, and
//     this failure is the result of it. Without the step it stays due forever, and every rotation tick
//     walks straight back onto a dead entry.
//
// Reports whether the entry was fresh — the transition callers log, since repeats are not news.
func (h healthSet) burn(key string) (fresh bool) {
	r := h.recs[key]
	if r == nil {
		h.recs[key] = &healthRec{state: stateSuspect, nextRetest: h.now() + suspectBackoff[0]}
		return true
	}
	if r.nextRetest <= h.now() {
		retestBackoff(r, h.now())
	}
	return false
}

// markTried pulls a tracked entry's wait forward to now because the pool is handing it out ANYWAY — the
// least-bad fallback, when nothing is healthy and nothing is due yet. It keeps `due` honest: an entry the
// pool is about to spend a live connection on is one whose wait is over in fact, so the verdict that comes
// back is allowed to walk its ladder. Without it every entry freezes at its first backoff step once the
// whole pool is burned, and the carrier hammers the same two endpoints forever.
func (h healthSet) markTried(key string) {
	if r := h.recs[key]; r != nil && r.nextRetest > h.now() {
		r.nextRetest = h.now()
	}
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
