package packet

import "sync"

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
	roll  func() bool
	spent int
}

// setRoll installs the carrier's redraw. A carrier that never calls this has no port axis.
func (p *portRung) setRoll(roll func() bool) {
	p.mu.Lock()
	p.roll = roll
	p.mu.Unlock()
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

	if roll() {
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
