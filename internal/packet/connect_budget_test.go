package packet

import (
	"net"
	"testing"
	"time"
)

// TestConnectBudgetIsOnlySpentOnTheDead is the number's whole justification, as an assertion rather than
// a comment: a connect that ANSWERS costs nothing like the budget, so shrinking the budget cannot cost a
// working edge anything. Measured against a live CDN edge it is ~115ms; a local listener is faster still,
// so this asserts the shape (orders of magnitude under) rather than a wall-clock figure that would flake.
func TestConnectBudgetIsOnlySpentOnTheDead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	b := &TCP{}
	start := time.Now()
	c, err := b.dialer(connectTimeout).Dial("tcp", ln.Addr().String())
	el := time.Since(start)
	if err != nil {
		t.Fatalf("dial to a live listener failed: %v", err)
	}
	c.Close()
	if el > connectTimeout/4 {
		t.Fatalf("a live connect took %v of a %v budget — the budget is not the slack it is meant to be", el, connectTimeout)
	}
}

// TestACannotLandPinEndsInsideTenSeconds is the operator-facing promise, and the reason connectTimeout is
// what it is. A pin is an interactive action with someone watching: a pick that cannot connect has to
// give the tunnel back quickly, not after a wait long enough to look like a hang.
//
// The budget is pinFailRelease attempts plus the reconnect backoff between them. It is arithmetic on the
// constants rather than a live run, because the wait being measured is a TIMEOUT — a real one would have
// to spend the very seconds it is asserting.
func TestACannotLandPinEndsInsideTenSeconds(t *testing.T) {
	// reconnectBase is jittered UP by at most jitterFrac's fraction, so take the worst case per gap.
	worstGap := time.Duration(0)
	for i := 0; i < 40; i++ {
		if g := nextReconnectDelay(0); g > worstGap {
			worstGap = g
		}
	}
	attempts := time.Duration(pinFailRelease) * connectTimeout
	gaps := time.Duration(pinFailRelease-1) * worstGap
	total := attempts + gaps

	if total > 10*time.Second {
		t.Fatalf("a pin that cannot land takes up to %v (%d attempts x %v + %d gaps x %v) — over the ten "+
			"seconds an operator is willing to watch. Lower connectTimeout or pinFailRelease.",
			total, pinFailRelease, connectTimeout, pinFailRelease-1, worstGap)
	}

	// ...and it must not be so tight that a lossy path loses a healthy edge. Linux re-sends the SYN at
	// t=0, 1 and 3 seconds, so a budget under 3s gives a path that drops two SYNs no third chance.
	if connectTimeout < 3*time.Second {
		t.Fatalf("connectTimeout is %v: under 3s the kernel's third SYN (t=3s) never goes out, so two lost "+
			"SYNs kill a healthy edge", connectTimeout)
	}
}
