package main

import (
	"strings"
	"testing"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/packet"
)

// splitCfg is a minimal valid ws client with SNI splitting on.
func splitCfg(mode string, ttl int) *Config {
	return &Config{
		Role: "client", Mode: "packet", Profile: "core", Transport: "ws",
		Peer: "203.0.113.9", TunAddr: "10.200.0.2/24",
		Crypto:   CryptoCfg{Enabled: true, PSK: "a-sufficiently-long-preshared-key"},
		WSTLS:    true,
		WSHost:   "cdn.example.com",
		SNISplit: true,
		SNIMode:  mode,
		SplitTTL: ttl,
	}
}

// TestSplitTTLIsCappedAtTheHopBudget: a disorder head whose TTL can reach the server arrives whole,
// which turns sni_mode=disorder into a plain split while every layer still reports disorder. The
// config must refuse the value rather than accept a knob that cannot do what it says.
func TestSplitTTLIsCappedAtTheHopBudget(t *testing.T) {
	for _, ttl := range []int{0, 1, 4, packet.MaxHopBudget} {
		if err := splitCfg("disorder", ttl).validate(); err != nil {
			t.Fatalf("split_ttl=%d is inside the budget but was refused: %v", ttl, err)
		}
	}
	for _, ttl := range []int{packet.MaxHopBudget + 1, 30, 64, 255} {
		err := splitCfg("disorder", ttl).validate()
		if err == nil {
			t.Fatalf("split_ttl=%d was ACCEPTED: the head reaches the server, so disorder is a no-op "+
				"and nothing anywhere says so", ttl)
		}
		if !strings.Contains(err.Error(), "split_ttl") {
			t.Fatalf("split_ttl=%d was refused for the wrong reason: %v", ttl, err)
		}
	}
	if err := splitCfg("disorder", -1).validate(); err == nil {
		t.Fatal("a negative split_ttl was accepted")
	}
}

// TestHopBudgetIsOneNumber: fake_ttl and split_ttl both mean "must die in transit", so they must not
// drift apart. The inject clamp is what fake_ttl is held to; MaxHopBudget is what split_ttl is held
// to, and the panel reads the same constant.
func TestHopBudgetIsOneNumber(t *testing.T) {
	if packet.MaxHopBudget <= 0 || packet.MaxHopBudget >= 64 {
		t.Fatalf("MaxHopBudget=%d is not a plausible in-transit hop budget: at or above a normal "+
			"initial TTL it reaches the peer, and at zero nothing is ever sent", packet.MaxHopBudget)
	}
}
