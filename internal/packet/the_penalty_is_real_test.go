//go:build linux

package packet

import (
	"net"
	"testing"
)

func TestLandingOnACondemnedEndpointIsNotARetestOfIt(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }
	p.fail("tun-probe")

	p.mu.Lock()
	was := *p.health.rec("a")
	p.mu.Unlock()

	p.mu.Lock()
	p.cur, p.chosen = 0, ""
	p.mu.Unlock()
	p.current()
	p.keepCursorOn("a")

	p.mu.Lock()
	got := *p.health.rec("a")
	p.mu.Unlock()
	if got.nextRetest != was.nextRetest || got.fails != was.fails {
		t.Errorf("the pool sat on a and that alone moved its sentence from %+v to %+v. Sitting on an "+
			"endpoint says nothing about it — the probe is the only thing that judges one, and the "+
			"only thing that clears it", was, got)
	}
}

func TestACondemnedPoolDoesNotClimbTheLadderWhileItsBackoffsRun(t *testing.T) {
	clk := int64(1000)
	dst := NewPeerPool([]string{"d1", "d2"}, 0)
	dst.now = func() int64 { return clk }
	rc := newRotationController(dst, nil)
	rot := func(bool) { dst.fail("tun-probe") }

	rc.fail(rot, nil)
	rc.fail(rot, nil)

	for i := 0; i < 60; i++ {
		clk += 3
		rc.fail(rot, nil)
	}
	dst.mu.Lock()
	defer dst.mu.Unlock()
	for _, a := range dst.addrs {
		r := dst.health.rec(a)
		if r == nil || r.state != stateSuspect || r.fails != 0 {
			t.Errorf("%s reached %s/fails=%d after 3 minutes of verdicts, with its first %ds backoff "+
				"still running. That is the whole sentence walked in the time the shortest step was "+
				"supposed to take, and every number the operator set on the way there means nothing",
				a, r.state, r.fails, suspectBackoff[0])
		}
	}
}

func TestTheTimerRetriesACondemnedEndpointOnlyWhenItsBackoffRanOut(t *testing.T) {
	clk := int64(1000)
	p := NewPeerPool([]string{"a", "b"}, 0)
	p.now = func() int64 { return clk }
	p.fail("tun-probe")
	p.fail("tun-probe")

	if a, moved := p.nextEndpoint(true); moved {
		t.Errorf("the rotation timer moved onto %q while its backoff was still running. Every move "+
			"costs a session, and sitting on an endpoint is not what makes it due again", a)
	}
	clk += suspectBackoff[0]
	if _, moved := p.nextEndpoint(true); !moved {
		t.Error("and once the backoff really has run out the timer must retry it, or a burned endpoint " +
			"is never looked at again")
	}
}

func helloRaw(t *testing.T) (*Raw, *capturingLink) {
	t.Helper()
	r := &Raw{isClient: true, profile: "tcp",
		psk: "hello-not-a-teardown-psk-0123456789", cipher: "chacha20-poly1305"}
	cl := &capturingLink{r: r}
	r.link = cl
	r.peer.Store(&net.IPAddr{IP: testDst})
	return r, cl
}

func TestTheFreeStepSaysHelloInsteadOfThrowingTheSessionAway(t *testing.T) {
	r, _ := helloRaw(t)
	greenSession(t, r)
	was := r.session.Load()

	if !r.rehandshake() {
		t.Fatal("the free step did not run")
	}
	if r.session.Load() != was {
		t.Error("the free step threw a live session away. Nothing crosses from that moment until the " +
			"handshake lands, and on a blocked path it never lands — the step meant to cost nothing " +
			"becomes the longest outage the ladder can cause")
	}
	if r.ci.Load() == nil {
		t.Error("...and it must actually ask: no ephemeral was staged, so no init went out")
	}
}

func TestAPortDrawIsPutOnTheWireEvenWithNoSession(t *testing.T) {
	r, cl := helloRaw(t)

	if !r.rollSourcePort() {
		t.Fatal("the draw did not happen")
	}
	if len(cl.sent) == 0 {
		t.Fatal("the draw picked a fresh source port and never tested it. The probe used to be a SEALED " +
			"ping, and send() returns without writing whenever there is no session — so during the one " +
			"state the draw exists for, it put nothing on the wire at all")
	}
}

func TestAPortDrawTestsThePathAndNotTheKey(t *testing.T) {
	r, cl := helloRaw(t)
	greenSession(t, r)

	if !r.rollSourcePort() {
		t.Fatal("the draw did not happen")
	}
	if r.ci.Load() == nil || len(cl.sent) == 0 {
		t.Fatal("the draw sent nothing a peer with a different key could answer")
	}
	if r.session.Load() == nil {
		t.Error("the draw dropped the session it already had — asking is free, and the old key must " +
			"keep carrying until a fresh answer replaces it")
	}
}
