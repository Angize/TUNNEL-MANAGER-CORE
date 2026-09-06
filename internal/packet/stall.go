package packet

import "time"

type stallWatch struct {
	seen    time.Time
	stalled bool
}

func (w *stallWatch) beat(rx bool, st *coreStatus, tag string, now time.Time) {
	if rx {
		w.seen = now
		if w.stalled {
			w.stalled = false
			st.reconnected(tag)
		}
		return
	}
	if w.seen.IsZero() || w.stalled || now.Sub(w.seen) < connIdle {
		return
	}
	w.stalled = true
	st.down("ping_timeout", tag)
}
