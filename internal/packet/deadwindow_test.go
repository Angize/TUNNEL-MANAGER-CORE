package packet

import (
	"testing"
	"time"
)

// TestDeadWindow verifies the per-tunnel self-heal deadline resolution: 0 keeps the default, a set
// value overrides it, and the >=2×keepalive clamp protects a healthy pinging link from mis-reaping.
func TestDeadWindow(t *testing.T) {
	ka := 15 * time.Second
	def := 60 * time.Second
	cases := []struct {
		name     string
		deadSecs int
		want     time.Duration
	}{
		{"unset keeps default", 0, 60 * time.Second},
		{"negative keeps default", -5, 60 * time.Second},
		{"honored above clamp", 45, 45 * time.Second},
		{"honored at clamp", 30, 30 * time.Second},
		{"below clamp raised to 2xka", 10, 30 * time.Second}, // 10s < 2×15s → 30s
		{"just below clamp raised", 20, 30 * time.Second},
		{"max honored", 300, 300 * time.Second},
	}
	for _, c := range cases {
		if got := deadWindow(ka, c.deadSecs, def); got != c.want {
			t.Errorf("%s: deadWindow(%v, %d, %v) = %v, want %v", c.name, ka, c.deadSecs, def, got, c.want)
		}
	}
}

// TestTCPSetDeadAfter proves the per-tunnel override tightens the TCP-family read deadline (b.idle)
// below the derived default, and is a no-op when unset. The default is deadMult x keepalive and
// nothing else -- it used to carry a 60s floor, which pinned it there for every keepalive at or
// under 15 and made the multiplier beside it inert.
func TestTCPSetDeadAfter(t *testing.T) {
	mk := func() *TCP { return &TCP{keepalive: 15 * time.Second, idle: idleFor(15 * time.Second)} }
	if b := mk(); b.idle != 45*time.Second { // 3x15s, and no floor rounding it up
		t.Fatalf("default idle = %v, want 45s", b.idle)
	}
	b := mk()
	b.SetDeadAfter(40)
	if b.idle != 40*time.Second {
		t.Errorf("after SetDeadAfter(40): idle = %v, want 40s", b.idle)
	}
	b2 := mk()
	b2.SetDeadAfter(0) // no-op
	if b2.idle != 45*time.Second {
		t.Errorf("SetDeadAfter(0) changed idle to %v, want the derived 45s untouched", b2.idle)
	}
	b3 := mk()
	b3.SetDeadAfter(10) // below 2×keepalive → clamped to 30s
	if b3.idle != 30*time.Second {
		t.Errorf("SetDeadAfter(10) with ka=15: idle = %v, want clamped 30s", b3.idle)
	}
}
