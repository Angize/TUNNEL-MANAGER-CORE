package main

import (
	"strings"
	"testing"
)

// A proactive rotation SHORTER than the keepalive tears every connection down before its first liveness
// proof: the carrier spends its life re-dialing, the endpoint never earns a verdict, and the tunnel reads as
// flapping while the interval is the cause. Nothing checked it -- all three knobs were only range-checked
// against 0. Driven through validate() so the check is tested where the operator meets it.
func TestRotationMayNotFireBeforeTheFirstKeepalive(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config, int)
	}{
		{"peer_rotate_secs", func(c *Config, v int) { c.PeerRotateSecs = v }},
		{"ws_rotate_secs", func(c *Config, v int) { c.WSRotateSecs = v }},
	} {
		c := validRaw()
		c.Keepalive = 30
		tc.set(c, 29)
		err := c.validate()
		if err == nil {
			t.Fatalf("%s=29 with keepalive=30 validated: a rotation that beats the first keepalive drops "+
				"every connection before it can prove the endpoint works", tc.name)
		}
		if !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), "keepalive") {
			t.Errorf("%s: the refusal must name the knob AND keepalive, got %q", tc.name, err.Error())
		}

		// Equal is fine -- one keepalive is exactly enough to prove the endpoint.
		c = validRaw()
		c.Keepalive = 30
		tc.set(c, 30)
		if err := c.validate(); err != nil {
			t.Errorf("%s=30 with keepalive=30 must be allowed: %v", tc.name, err)
		}

		// 0 means "rotate only on failure" and must stay allowed however large keepalive is.
		c = validRaw()
		c.Keepalive = 120
		tc.set(c, 0)
		if err := c.validate(); err != nil {
			t.Errorf("%s=0 (failover-only) must stay allowed: %v", tc.name, err)
		}
	}
}

// flux_rotate_secs is the SHAPE epoch, not an endpoint rotation: both ends derive the shape from
// HKDF(PSK, epoch) off their own clocks and no packet moves, so nothing is torn down and an epoch shorter
// than the keepalive is legitimate. The first version of the floor lumped it in with the endpoint knobs and
// would have refused working configs -- pin the distinction so it cannot be re-conflated.
func TestFluxEpochIsNotAnEndpointRotation(t *testing.T) {
	c := validRaw()
	c.Transport = "flux"
	c.Keepalive = 60
	c.FluxRotateSecs = 5 // twelve shape changes per keepalive: fine, no connection is dropped
	if err := c.validate(); err != nil {
		t.Fatalf("a flux epoch shorter than the keepalive must be allowed -- it rotates the SHAPE off the "+
			"clock and drops nothing: %v", err)
	}
	// ...while an endpoint rotation on the SAME config is still floored.
	c = validRaw()
	c.Transport = "flux"
	c.Keepalive = 60
	c.PeerRotateSecs = 5
	if err := c.validate(); err == nil {
		t.Error("peer_rotate_secs=5 with keepalive=60 must still be refused; only the shape epoch is exempt")
	}
}

// The check must use the DEFAULTED keepalive, not the raw field: a config that leaves keepalive at 0 gets 15,
// and a rotation under 15 is just as broken there as when the operator typed 15.
func TestRotationFloorUsesTheDefaultedKeepalive(t *testing.T) {
	c := validRaw()
	c.Keepalive = 0 // -> defaults to 15
	c.PeerRotateSecs = 5
	if err := c.validate(); err == nil {
		t.Fatal("peer_rotate_secs=5 with an unset keepalive validated; the default is 15, so 5 still " +
			"rotates before the first ping")
	}
	c = validRaw()
	c.Keepalive = 0
	c.PeerRotateSecs = 15
	if err := c.validate(); err != nil {
		t.Errorf("peer_rotate_secs=15 against the default keepalive of 15 must pass: %v", err)
	}
}

// SO_SNDBUF/SO_RCVBUF override the kernel's autotuning, so a pin BELOW its own default is worse than not
// pinning: it caps the carrier's window at that size for the connection's whole life. A byte count someone
// meant as MiB is exactly how that happens. Negative still means "leave the kernel alone".
func TestSockBufIsFlooredNotJustCapped(t *testing.T) {
	const floor = 64 << 10
	// The clamps live in applyDefaults(), which LoadConfig runs after validate(); mirror that order.
	settle := func(c *Config) error {
		if err := c.validate(); err != nil {
			return err
		}
		c.applyDefaults()
		return nil
	}
	for _, in := range []int{1, 1024, 4096, floor - 1} {
		c := validRaw()
		c.SockBuf = in
		if err := settle(c); err != nil {
			t.Fatalf("sock_buf=%d should be clamped, not refused: %v", in, err)
		}
		if c.SockBuf != floor {
			t.Errorf("sock_buf=%d was pinned as %d; a pin under the kernel default kills autotuning "+
				"(want the %d floor)", in, c.SockBuf, floor)
		}
	}
	// At and above the floor the operator's number is honoured verbatim, up to the existing cap.
	for _, in := range []int{floor, 1 << 20, 64 << 20} {
		c := validRaw()
		c.SockBuf = in
		if err := settle(c); err != nil {
			t.Fatalf("sock_buf=%d: %v", in, err)
		}
		if c.SockBuf != in {
			t.Errorf("sock_buf=%d was rewritten to %d; only values under the floor may move", in, c.SockBuf)
		}
	}
	// 0 still means "use the default", and negative still means "do not pin at all".
	c := validRaw()
	c.SockBuf = 0
	if err := settle(c); err != nil || c.SockBuf != 4<<20 {
		t.Errorf("sock_buf=0 must become the 4 MiB default, got %d (%v)", c.SockBuf, err)
	}
	c = validRaw()
	c.SockBuf = -1
	if err := settle(c); err != nil || c.SockBuf >= 0 {
		t.Errorf("sock_buf=-1 means leave the kernel alone and must stay negative, got %d (%v)", c.SockBuf, err)
	}
	// And the cap the floor was added next to still holds.
	c = validRaw()
	c.SockBuf = 128 << 20
	if err := settle(c); err != nil || c.SockBuf != 64<<20 {
		t.Errorf("sock_buf=128MiB must cap at 64MiB, got %d (%v)", c.SockBuf, err)
	}
}
