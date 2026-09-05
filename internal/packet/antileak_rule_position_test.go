//go:build linux

package packet

import (
	"errors"
	"testing"
)

func TestEveryAntiLeakRuleGoesInAtTheTopOfItsChain(t *testing.T) {
	var argv [][]string
	restore := iptablesRun

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
		{"raw/udp", "OUTPUT", func() { _, _ = addRawDrop(rawLeak{peer: testDst, profile: "udp", isClient: true}, "core42") }},
		{"raw/tcp", "OUTPUT", func() { _, _ = addRawDrop(rawLeak{peer: testDst, profile: "tcp", isClient: true}, "core42") }},
		{"raw/tcp server", "OUTPUT", func() { _, _ = addRawDrop(rawLeak{peer: testDst, profile: "tcp"}, "core42") }},
		{"raw/icmp", "OUTPUT", func() { _, _ = addRawDrop(rawLeak{peer: testDst, profile: "icmp", marked: true}, "core42") }},
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

var errRuleAbsent = errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")
