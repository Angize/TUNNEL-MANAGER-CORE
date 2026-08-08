package packet

import (
	"fmt"
	"testing"
	"time"
)

// keepaliveInterval must stay inside [0.6,1.3]×base so a live-but-idle client always pings well
// within the server's deadMult×keepalive read deadline and pingLossThreshold dead-detection stays
// bounded. A single out-of-band value could get a healthy tunnel reaped or slow self-heal.
func TestKeepaliveIntervalBounds(t *testing.T) {
	base := 15 * time.Second
	lo := time.Duration(float64(base) * 0.6)
	hi := time.Duration(float64(base) * 1.3)
	for i := 0; i < 50000; i++ {
		d := keepaliveInterval(base, "some-preshared-key")
		if d < lo || d > hi {
			t.Fatalf("interval %v out of bounds [%v,%v]", d, lo, hi)
		}
	}
}

func TestKeepaliveIntervalNonPositive(t *testing.T) {
	if got := keepaliveInterval(0, "x"); got != 0 {
		t.Fatalf("base 0 => %v, want 0", got)
	}
	if got := keepaliveInterval(-5*time.Second, "x"); got != -5*time.Second {
		t.Fatalf("negative base => %v, want it unchanged", got)
	}
}

// Different PSKs must land at different MEAN periods, so a fleet does not share one recoverable
// keepalive constant and flows do not beacon in lockstep. Estimate each tunnel's mean over many
// draws and require the set of means to actually spread.
func TestKeepaliveIntervalPerTunnelSpread(t *testing.T) {
	base := 15 * time.Second
	meanOf := func(psk string) float64 {
		const n = 8000
		var sum float64
		for i := 0; i < n; i++ {
			sum += float64(keepaliveInterval(base, psk)) / float64(base)
		}
		return sum / n
	}
	min, max := 2.0, 0.0
	for i := 0; i < 40; i++ {
		m := meanOf(fmt.Sprintf("tunnel-psk-%d", i))
		if m < min {
			min = m
		}
		if m > max {
			max = m
		}
	}
	if max-min < 0.10 {
		t.Fatalf("per-tunnel mean spread only %.3f across 40 tunnels; expected distinct fleet phases", max-min)
	}
}

// The per-tunnel mean is DETERMINISTIC in the PSK: the same PSK must estimate to the same mean
// across independent sampling runs (so a reconnect keeps the tunnel's phase, and the shift is a
// stable per-tunnel property rather than per-connection noise).
func TestKeepaliveIntervalPerTunnelStable(t *testing.T) {
	base := 15 * time.Second
	meanOf := func() float64 {
		const n = 20000
		var sum float64
		for i := 0; i < n; i++ {
			sum += float64(keepaliveInterval(base, "stable-tunnel")) / float64(base)
		}
		return sum / n
	}
	a, b := meanOf(), meanOf()
	if diff := a - b; diff > 0.02 || diff < -0.02 {
		t.Fatalf("same PSK mean not stable across runs: %.3f vs %.3f", a, b)
	}
}

// recentData gates the opportunistic keepalive: true suppresses the active connection's ping. A fresh
// connection must NOT suppress, or it could be idle-reaped before the first packet; recent INBOUND data
// must; data older than the window must resume pinging. It drives the real inbound path rather than
// storing the stamp by hand, because the question that matters is WHO is allowed to stamp it.
func TestRecentData(t *testing.T) {
	dev, _ := tunPair(t, "recentdata")
	b := &TCP{keepalive: 15 * time.Second, dev: dev}
	if b.recentData() {
		t.Fatal("no data yet: recentData must be false so a fresh conn keeps its keepalive")
	}
	b.handleFrame(&connFramer{}, typeData, []byte{0x45, 0x00, 0x00, 0x14})
	if !b.recentData() {
		t.Fatal("an inbound DATA frame must set recentData: the peer just proved it is answering, " +
			"so the standalone ping is redundant for this period")
	}
	b.lastRxData.Store(time.Now().Add(-2 * b.keepalive).UnixNano())
	if b.recentData() {
		t.Fatal("data older than one keepalive: recentData must be false so pinging resumes")
	}
	// A ping or a pong is not data and must never suppress the ping that detects a dead peer.
	b.handleFrame(&connFramer{}, typePong, nil)
	if b.recentData() {
		t.Fatal("a pong is not DATA: it must not extend the suppression window")
	}
}
