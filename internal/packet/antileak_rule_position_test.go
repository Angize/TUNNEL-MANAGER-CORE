//go:build linux

package packet

import (
	"errors"
	"testing"
)

// Every anti-leak rule goes in at the TOP of its chain, never appended.
//
// Appended is not "installed": the answers this carrier provokes are conntrack RELATED/ESTABLISHED,
// and a host running ufw jumps to ufw-before-output from the top of OUTPUT, where
// `--ctstate RELATED,ESTABLISHED -j ACCEPT` sits. ACCEPT ends the traversal, so an appended DROP is
// never reached — while runRule reports success and the log says "anti-leak scoped to …", which is
// what the operator reads as protection. Measured in a netns lab with a ufw-shaped chain: the
// kernel's answer reaches the client with -A and does not with -I, on all three noisy profiles.
//
// Position is not observable from the rule itself, so what is pinned here is the argv: the seam every
// rule really goes through.
func TestEveryAntiLeakRuleGoesInAtTheTopOfItsChain(t *testing.T) {
	var argv [][]string
	restore := iptablesRun
	// -C is runRule asking whether the rule is there already; answering "no" is what lets the install
	// run, and those probes are not installs so they are not recorded.
	iptablesRun = func(a []string) ([]byte, error) {
		if indexOfArg(a, "-C") >= 0 {
			return nil, errRuleAbsent
		}
		argv = append(argv, append([]string(nil), a...))
		return nil, nil
	}
	defer func() { iptablesRun = restore }()

	for _, tc := range []struct {
		name  string
		chain string
		run   func()
	}{
		{"raw/udp", "OUTPUT", func() { _, _ = addRawDrop(testDst, "udp", "core42", 0, true, false, false) }},
		{"raw/tcp", "OUTPUT", func() { _, _ = addRawDrop(testDst, "tcp", "core42", 0, true, false, false) }},
		{"raw/tcp server", "OUTPUT", func() { _, _ = addRawDrop(testDst, "tcp", "core42", 0, false, false, true) }},
		{"raw/icmp", "OUTPUT", func() { _, _ = addRawDrop(testDst, "icmp", "core42", 0, false, true, false) }},
		{"spoof decoy", "PREROUTING", func() { addAntiLeak(253, testDst, "core42") }},
		{"flux/udp", "PREROUTING", func() { _, _ = addFluxDrop(testDst, "udp", "core42") }},
		{"flux/stun", "PREROUTING", func() { _, _ = addFluxDrop(testDst, "stun", "core42") }},
	} {
		argv = nil
		tc.run()
		if len(argv) == 0 {
			t.Errorf("%s: installed nothing", tc.name)
			continue
		}
		for _, a := range argv {
			i := indexOfArg(a, tc.chain)
			if i <= 0 {
				t.Errorf("%s: no %s in %v", tc.name, tc.chain, a)
				continue
			}
			if a[i-1] != "-I" {
				t.Errorf("%s: the rule is %s'd into %s: %v — anything above it that ACCEPTs "+
					"(ufw's RELATED,ESTABLISHED, measured) means it never runs, while the log says it is installed",
					tc.name, a[i-1], tc.chain, a)
			}
		}
	}
}

func indexOfArg(argv []string, want string) int {
	for i, a := range argv {
		if a == want {
			return i
		}
	}
	return -1
}

// errRuleAbsent is what iptables -C reports when the rule is not in the chain: the answer that lets
// an install proceed. Shared by the fakes that must not have their installs skipped.
var errRuleAbsent = errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")
