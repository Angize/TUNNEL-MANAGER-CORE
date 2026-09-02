package main

import (
	"strings"
	"testing"
)

func TestRotationMayNotFireBeforeTheJudgeCanSpeak(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config, int)
	}{
		{"peer_rotate_secs", func(c *Config, v int) { c.PeerRotateSecs = v }},
		{"ws_rotate_secs", func(c *Config, v int) { c.WSRotateSecs = v }},
	} {
		c := validRaw()
		tc.set(c, minRotateSecs-1)
		err := c.validate()
		if err == nil {
			t.Fatalf("%s at %ds validated. The node needs two bad sweeps to call a tunnel red, so a "+
				"rotation faster than %ds moves the endpoint on before anything has judged it",
				tc.name, minRotateSecs-1, minRotateSecs)
		}
		if !strings.Contains(err.Error(), tc.name) {
			t.Errorf("%s: the refusal must name the knob, got %q", tc.name, err.Error())
		}

		c = validRaw()
		tc.set(c, minRotateSecs)
		if err := c.validate(); err != nil {
			t.Errorf("%s at the floor itself must be allowed: %v", tc.name, err)
		}

		c = validRaw()
		tc.set(c, 0)
		if err := c.validate(); err != nil {
			t.Errorf("%s=0 (failover-only) must stay allowed: %v", tc.name, err)
		}
	}
}

func TestSockBufIsFlooredNotJustCapped(t *testing.T) {
	const floor = 64 << 10

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

	c = validRaw()
	c.SockBuf = 128 << 20
	if err := settle(c); err != nil || c.SockBuf != 64<<20 {
		t.Errorf("sock_buf=128MiB must cap at 64MiB, got %d (%v)", c.SockBuf, err)
	}
}
