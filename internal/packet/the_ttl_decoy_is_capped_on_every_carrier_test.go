//go:build linux

package packet

import "testing"

// A low-TTL desync decoy only works if it dies in the network before it reaches the peer: the DPI in the
// middle sees it, the peer never does. specsTCP() has always capped the TTL at the 8-hop budget; specs(),
// which every non-TCP carrier (raw, flux, spoof) uses, did not -- so an operator who set fake_ttl=200 on a
// raw tunnel shipped a "decoy" that sailed all the way to the peer and desynced nobody. Both paths now cap.
func TestTheTTLDecoyIsCappedOnEveryCarrier(t *testing.T) {
	for _, mode := range []string{"ttl", "both"} {
		d := newDesyncCfg(true, 200, 4, mode)
		for _, s := range d.specs() {
			if s.badSum {
				continue
			}
			if s.ttl > injectMaxTTL {
				t.Fatalf("mode=%s: a low-TTL decoy has ttl=%d, above the %d-hop budget", mode, s.ttl, injectMaxTTL)
			}
		}
	}

	// a TTL already within budget is left exactly as the operator asked
	for _, s := range newDesyncCfg(true, 5, 2, "ttl").specs() {
		if !s.badSum && s.ttl != 5 {
			t.Fatalf("an in-budget ttl was rewritten: got %d, want 5", s.ttl)
		}
	}

	// the TCP path was already capped; this pins it so the two carriers never drift apart again
	for _, s := range newDesyncCfg(true, 200, 4, "ttl").specsTCP() {
		if s.ttl > injectMaxTTL {
			t.Fatalf("specsTCP regressed: ttl=%d", s.ttl)
		}
	}
}
