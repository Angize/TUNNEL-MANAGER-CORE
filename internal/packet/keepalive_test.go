package packet

import (
	"fmt"
	"testing"
	"time"
)

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

func TestRecentData(t *testing.T) {
	dev, _ := tunPair(t, "recentdata")
	b := &TCP{dev: dev, ping: pingEvery}
	if b.recentData() {
		t.Fatal("no data yet: recentData must be false so a fresh conn keeps its keepalive")
	}
	b.handleFrame(&connFramer{}, typeData, []byte{0x45, 0x00, 0x00, 0x14})
	if !b.recentData() {
		t.Fatal("an inbound DATA frame must set recentData: the peer just proved it is answering, " +
			"so the standalone ping is redundant for this period")
	}
	b.lastRxData.Store(time.Now().Add(-2 * pingEvery).UnixNano())
	if b.recentData() {
		t.Fatal("data older than one ping period: recentData must be false so pinging resumes")
	}

	b.handleFrame(&connFramer{}, typePong, nil)
	if b.recentData() {
		t.Fatal("a pong is not DATA: it must not extend the suppression window")
	}
}
