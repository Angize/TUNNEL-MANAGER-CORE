package packet

type healthSet struct {
	recs map[string]*healthRec

	now func() int64
}

func newHealthSet(clock *func() int64) healthSet {
	return healthSet{recs: map[string]*healthRec{}, now: func() int64 { return (*clock)() }}
}

func (h healthSet) rec(key string) *healthRec { return h.recs[key] }

func (h healthSet) healthy(key string) bool { return h.recs[key] == nil }

func (h healthSet) due(key string) bool {
	r := h.recs[key]
	return r != nil && r.nextRetest <= h.now()
}

func (h healthSet) eligible(key string) bool {
	r := h.recs[key]
	return r == nil || r.nextRetest <= h.now()
}

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

func (h healthSet) clear(key string) bool {
	_, had := h.recs[key]
	delete(h.recs, key)
	return had
}

func (h healthSet) clearAll() bool {
	if len(h.recs) == 0 {
		return false
	}
	clear(h.recs)
	return true
}

// End ONE entry's wait. The operator asked for this key, not for the whole pool: a single button that
// zeroed every wait made the other entries' backoff a lie.
func (h healthSet) retestNow(key string) bool {
	r := h.recs[key]
	if r == nil {
		return false
	}
	r.nextRetest = h.now()
	return true
}

func (h healthSet) countEligible(keys []string) int {
	n := 0
	for _, k := range keys {
		if h.eligible(k) {
			n++
		}
	}
	return n
}
