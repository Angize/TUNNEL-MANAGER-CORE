//go:build linux

package packet

import "testing"

// The status file has to say WHY the carrier moved, because the two reasons are opposite news.
//
// A scheduled rotation is the clock coming due on a healthy tunnel. A forced one is the ladder walking
// off an endpoint that stopped carrying traffic. Both used to be published as the identical event --
// kind "down", code "<axis>-rotate", same detail -- so the panel painted a green «چرخش آی‌پیِ مقصد»
// for a path that had just failed, and an operator watching the log could not tell a tunnel that is
// working from one that is limping.
//
// The core already knew the difference: only the forced one sets wasDown, which is what arms the "up"
// event on the next reconnect. This asserts the kind now carries the same truth to the wire, on every
// carrier, and that the wasDown half still agrees with it -- one is useless without the other, since
// the panel reads the kind and the operator reads the recovery line.
func TestAScheduledRotationIsNotPublishedAsAnOutage(t *testing.T) {
	eachCarrier(t, func(t *testing.T, r *poolRig) {
		r.rotLow(true)

		if got := r.eventDetails(t, "rot", r.lowRotate); len(got) != 1 {
			t.Fatalf("%s: a scheduled rotation published %d rot/%s events, want 1: %+v",
				r.name, len(got), r.lowRotate, r.status(t).Events)
		}
		if got := r.eventDetails(t, "down", r.lowRotate); len(got) != 0 {
			t.Fatalf("%s: a scheduled rotation was published as the tunnel going down (%d down/%s "+
				"events) — the panel cannot tell it from a path that failed", r.name, len(got), r.lowRotate)
		}

		r.st.reconnected("after-the-schedule")
		if hasKind(r.status(t).Events, "up") {
			t.Fatalf("%s: a scheduled rotation armed the recovery report — nothing had gone wrong", r.name)
		}

		r.rotLow(false)

		if got := r.eventDetails(t, "down", r.lowRotate); len(got) != 1 {
			t.Fatalf("%s: a forced rotation published %d down/%s events, want 1: %+v",
				r.name, len(got), r.lowRotate, r.status(t).Events)
		}
		if got := r.eventDetails(t, "rot", r.lowRotate); len(got) != 1 {
			t.Fatalf("%s: a forced rotation was published as a scheduled one (%d rot/%s events, want "+
				"only the scheduled one from earlier)", r.name, len(got), r.lowRotate)
		}

		r.st.reconnected("after-the-failure")
		if !hasKind(r.status(t).Events, "up") {
			t.Fatalf("%s: a forced rotation did not arm the recovery report, so the operator never "+
				"learns the tunnel came back", r.name)
		}
	})
}
