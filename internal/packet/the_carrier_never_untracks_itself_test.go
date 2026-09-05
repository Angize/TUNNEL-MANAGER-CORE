//go:build linux

package packet

import (
	"errors"
	"strings"
	"testing"
)

// A conntrack bypass for the carrier's own flows was added and then measured to kill the tunnel
// outright on an ordinary firewalled client: `ufw default deny incoming` accepts the return traffic
// only because it is ESTABLISHED, and an untracked packet is not ESTABLISHED, so every reply the
// server sent was dropped by the client's own policy. Measured 100% loss with rotation on against 0%
// with it off, on the same box, with only the policy changed.
//
// The carrier must therefore never make its own traffic untracked. It may install anti-leak DROPs,
// and nothing else: a rule that changes how the HOST treats the packets is not ours to add, because
// we cannot see the policy it lands in.
var errCheckMiss = errors.New("no such rule")

func TestTheCarrierNeverUntracksItsOwnTraffic(t *testing.T) {
	seen := map[string][][]string{}
	restore := iptablesRun
	iptablesRun = func(args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		for _, a := range args {
			if a == "-C" {
				return nil, errCheckMiss
			}
		}
		seen[joined] = append(seen[joined], args)
		return nil, nil
	}
	defer func() { iptablesRun = restore }()

	for _, profile := range RawProfileNames() {
		for _, isClient := range []bool{true, false} {
			_, _ = addRawDrop(rawLeak{peer: testDst, profile: profile, port: 443, isClient: isClient, marked: true}, "core42")
		}
	}

	for joined, calls := range seen {
		for _, banned := range []string{"NOTRACK", "--notrack", "-j CT", "-t raw"} {
			if strings.Contains(joined, banned) {
				t.Errorf("the carrier installed %q (%d time(s)): %s\n"+
					"A rule in the raw table, or any CT target, changes the conntrack state the HOST's own "+
					"policy is written against. On a box whose only inbound allowance is "+
					"--ctstate ESTABLISHED, that silently drops every reply and the tunnel reads as 100%% loss.",
					banned, len(calls), joined)
			}
		}
	}
}
