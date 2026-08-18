package packet

import (
	"sync"
	"time"
)

// portTries is how many source ports the ladder redraws before it will condemn anything. Measured on
// the live Iran path: about one port in six is blackholed toward a given destination, and the draws are
// independent, so two of them clear it better than 97 times in a hundred. A third buys a fraction of a
// percent and costs another measurement round, which is the expensive part.
const portTries = 2

// portRung is the free step the ladder takes before it condemns anything: redraw the source port and
// let the next measurement judge. It costs no session, moves no endpoint and blames nobody, so it is
// spent first — and until it IS spent, nothing else may be burned.
//
// That order is the whole point. The blocking that made this necessary is keyed on the combination of
// destination and source PORT, so the tunnel dies without any endpoint being at fault; a walk that
// starts at the destination answers by condemning a healthy server, and the port that actually did it
// is redrawn on an unrelated schedule minutes later, which reads as the destination change having
// worked.
type portRung struct {
	mu sync.Mutex
	// roll redraws the port and reports whether it moved. nil on a carrier with no port axis — a
	// portless raw profile, or one whose ports are derived rather than chosen — which leaves the ladder
	// starting where it always did.
	//
	// step says whether this redraw is a ladder STEP — local evidence, or a verdict spending the rung —
	// rather than the scheduled refresh, which moves the port of a tunnel that is carrying perfectly
	// well and is therefore not an event about anything.
	roll  func(step bool) bool
	spent int
	// dead reports that the CURRENT 4-tuple has stopped carrying — the carrier's own evidence, which is
	// rung zero's other trigger. ready reports a session on that path. every is the scheduled re-roll
	// interval, zero on a carrier that keeps its port still. All nil/zero until setRefresh.
	dead  func(time.Time) bool
	ready func() bool
	every time.Duration
	next  time.Time
}

// setRoll installs the carrier's redraw. A carrier that never calls this has no port axis.
func (p *portRung) setRoll(roll func(step bool) bool) {
	p.mu.Lock()
	p.roll = roll
	p.mu.Unlock()
}

// setRefresh installs what the ladder needs to drive the port on its own beat. A carrier that never
// calls this still has a rung — a verdict can spend it — but nothing moves the port between verdicts.
func (p *portRung) setRefresh(dead func(time.Time) bool, ready func() bool, every time.Duration) {
	p.mu.Lock()
	p.dead, p.ready, p.every = dead, ready, every
	p.mu.Unlock()
}

// tick is the ladder's beat on the source port, and the only place it moves outside a verdict. It runs
// on the pin poller, which is the ladder's own one-second tick.
//
// Two reasons, and they are not the same kind of thing:
//
//   - LOCAL EVIDENCE — the return direction of this tuple has gone. That is rung zero's own trigger, so
//     it rolls at once, whatever else is happening.
//   - THE SCHEDULE — a carrying tuple that never moves is a fixed one, which is what the rotation
//     exists to avoid. That is a refresh, not a step, so it is taken only while the tunnel is green and
//     no verdict landed this beat: it must never move the path in the middle of the judge's experiment.
//
// The reactive roll is deliberately NOT charged to the rung's budget. That budget is refilled only by
// traffic crossing, and until the ladder grows a path-exhausted backoff to refill it otherwise, a
// budgeted reactive roll would strand a tunnel whose downstream is blackholed on both draws — where the
// loop this replaced kept drawing until one worked.
func (p *portRung) tick(now time.Time, judged bool) {
	p.mu.Lock()
	roll, dead, ready, every := p.roll, p.dead, p.ready, p.every
	if roll == nil {
		p.mu.Unlock()
		return
	}
	if p.next.IsZero() && every > 0 {
		p.next = now.Add(jitterFrac(every))
	}
	due := every > 0 && now.After(p.next)
	p.mu.Unlock()

	reactive := dead != nil && dead(now)
	if !reactive && (!due || judged || (ready != nil && !ready())) {
		return
	}
	// Re-armed for BOTH reasons: a reactive roll has just given the tuple a fresh start, so the
	// schedule owes it a full interval rather than whatever was left of the old one.
	p.mu.Lock()
	if every > 0 {
		p.next = now.Add(jitterFrac(every))
	}
	p.mu.Unlock()
	roll(reactive)
}

// armed reports that the ladder has a port to drive on its own beat. The poller asks so it starts for
// a carrier whose ONLY reason to tick is the port — before this the port moved on a goroutine that ran
// unconditionally, and gating the beat on a pool or a mailbox alone would have left such a carrier's
// port fixed for the life of the tunnel.
func (p *portRung) armed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.roll != nil && (p.every > 0 || p.dead != nil)
}

// try spends one draw if any are left, and reports whether the ladder should stop here — the port has
// moved, the tunnel is on a different combination, and the next measurement judges that one instead of
// something being burned for this one's silence.
//
// The draw is TAKEN before the redraw runs and handed back if it did not move, rather than counted
// after. Checking the budget and then spending it in two separate holds lets two callers both find it
// open and both redraw, which spends the whole allowance on one round; and the redraw cannot run under
// the lock, because it puts a packet on the wire.
func (p *portRung) try() bool {
	p.mu.Lock()
	roll := p.roll
	if roll == nil || p.spent >= portTries {
		p.mu.Unlock()
		return false
	}
	p.spent++
	p.mu.Unlock()

	if roll(true) { // a verdict spending the rung is a step, whatever the local evidence says
		return true
	}
	p.mu.Lock() // nothing drawn: the axis exists but could not move, so it was not a step
	p.spent--
	p.mu.Unlock()
	return false
}

// restart refills the draws. A measurement that found traffic crossing settles the question this rung
// was asking, so the next outage gets the full budget rather than the remainder of the last one.
func (p *portRung) restart() {
	p.mu.Lock()
	p.spent = 0
	p.mu.Unlock()
}
