package packet

import (
	"testing"
	"time"
)

// The reconnect backoff doubles to a minute, and the dial loop only reads the pool at the top of an
// attempt. So a ladder that walks the pool onto a different edge while the loop is inside that sleep
// changes nothing until the sleep runs out on its own: the tunnel goes on waiting to redial a target
// nobody points at any more. udp and raw have never had this hole -- rotatePeerUDP and rotatePeerRaw
// both wakeLoop their carrier the moment the destination changes.
func TestARotationEndsTheReconnectSleep(t *testing.T) {
	const dead, sni = "dead:443", "front-a"
	b, pp, _ := edgeCarrier(t, []string{dead, "good:443"}, snis(sni))

	b.pretendDown()
	b.noteAttempt(dead, sni)

	woke := make(chan time.Duration, 1)
	go func() {
		left, _ := b.waitToRedial(30 * time.Second)
		woke <- left
	}()

	if !b.tunFail(t, dead, sni) {
		t.Fatal("the verdict did not step the pool; the test has nothing to wake on")
	}
	if got := pp.current(); got == dead {
		t.Fatalf("the pool is still on %s", got)
	}

	select {
	case left := <-woke:
		if left != 0 {
			t.Errorf("the sleep ended with %v of backoff still owed; a redial that follows the pool "+
				"starts from zero", left)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the rotation did not end the reconnect sleep — the dial loop is still waiting on the " +
			"edge the ladder walked off")
	}
}

// And the token may not be banked: a rotation that lands while the carrier is connected must not buy a
// free skip past the first backoff of the NEXT outage.
func TestAWakeIsNotBanked(t *testing.T) {
	b, _, _ := edgeCarrier(t, []string{"a:443", "b:443"}, snis("front-a"))

	wakeLoop(b.wake)
	select {
	case <-b.wake:
	default:
		t.Fatal("setup: the wake was not delivered")
	}

	start := time.Now()
	if _, stop := b.waitToRedial(120 * time.Millisecond); stop {
		t.Fatal("the wait reported the carrier closed")
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Errorf("the backoff was skipped after only %v; a drained wake must not shorten it",
			time.Since(start))
	}
}
