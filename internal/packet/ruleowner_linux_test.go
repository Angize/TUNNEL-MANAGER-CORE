//go:build linux

package packet

import (
	"reflect"
	"strings"
	"testing"
)

// TestEveryRuleNamesItsOwner: a rule with no owner is an orphan nobody can attribute, and that is how
// two production boxes ended up carrying a --dport 4500 rule from a deleted tunnel and one ICMP rule
// twice. The node sweeps `tnl:<tun>` before a build and after a stop, which only works if the rule
// carries the tag in the first place.
func TestEveryRuleNamesItsOwner(t *testing.T) {
	got := ownerMatch("core42")
	want := []string{"-m", "comment", "--comment", "tnl:core42"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ownerMatch = %v, want %v", got, want)
	}
	if len(got) > 0 && got[len(got)-1] != ruleOwnerPrefix+"core42" {
		t.Error("the tag must be the prefix plus the tun name, or the node's sweep looks for the wrong string")
	}
	// A carrier with no device tags nothing rather than tagging the prefix alone: `tnl:` would be a
	// tag every tunnel matches, and the first sweep would take out the whole fleet's rules.
	if o := ownerMatch(""); o != nil {
		t.Errorf("an unnamed carrier must tag nothing, got %v -- %q would match every tunnel", o, ruleOwnerPrefix)
	}
}

// TestTheRemovalMatchesTheInstall drives the REAL installers and captures the argv they hand iptables,
// for the install and for the teardown they return. An earlier version of this test compared the rule
// BUILDERS instead, and a RED proof showed it stayed green when the owner was stripped from the actual
// removal -- it was testing a helper, not the path. iptables -D deletes by matching the full spec, so
// a removal missing one match silently removes nothing and the rule outlives its core.
func TestTheRemovalMatchesTheInstallOnTheRealPath(t *testing.T) {
	var argv [][]string
	old := iptablesRun
	iptablesRun = func(a []string) ([]byte, error) {
		argv = append(argv, append([]string(nil), a...))
		return nil, nil
	}
	defer func() { iptablesRun = old }()

	for _, tc := range []struct {
		name string
		run  func() func()
	}{
		{"raw tcp", func() func() { rm, _ := addRawDrop(testDst, "tcp", "core42", 0, true, false, false); return rm }},
		{"raw icmp", func() func() { rm, _ := addRawDrop(testDst, "icmp", "core42", 0, false, true, false); return rm }},
		{"spoof decoy", func() func() { return addAntiLeak(253, testDst, "core42") }},
		{"flux udp", func() func() { rm, _ := addFluxDrop(testDst, "udp", "core42"); return rm }},
	} {
		argv = nil
		rm := tc.run()
		installs := append([][]string(nil), argv...)
		if len(installs) == 0 {
			t.Errorf("%s: installed nothing", tc.name)
			continue
		}
		for _, a := range installs {
			if !strings.Contains(strings.Join(a, " "), "tnl:core42") {
				t.Errorf("%s: installed a rule with no owner: %v", tc.name, a)
			}
		}
		if rm == nil {
			t.Errorf("%s: no teardown returned, so the rules can never be removed", tc.name)
			continue
		}
		argv = nil
		rm()
		removals := argv
		if len(removals) != len(installs) {
			t.Errorf("%s: %d installs but %d removals", tc.name, len(installs), len(removals))
			continue
		}
		for i := range installs {
			in, out := installs[i], removals[i]
			if len(in) != len(out) {
				t.Errorf("%s[%d]: install %v / removal %v -- -D matches the FULL spec, so this deletes nothing",
					tc.name, i, in, out)
				continue
			}
			for j := range in {
				a, b := in[j], out[j]
				if a == b {
					continue
				}
				if a != "-A" || b != "-D" { // the ONLY difference allowed anywhere in the argv
					t.Errorf("%s[%d]: arg %d differs (%q install, %q removal) -- the rule survives its own teardown",
						tc.name, i, j, a, b)
				}
			}
		}
	}
}

func TestRuleBuildersStayInStep(t *testing.T) {
	owner := ownerMatch("core42")
	for _, tc := range []struct {
		name  string
		match []string
	}{
		{"tcp RST drop", rawDropMatches(testDst, "tcp", 0, true, false, false)[0]},
		{"icmp reply drop", rawDropMatches(testDst, "icmp", 0, false, true, false)[0]},
	} {
		add := append(append([]string{"-A", "OUTPUT"}, append(append([]string{}, tc.match...), "-j", "DROP")...), owner...)
		del := append(append([]string{"-D", "OUTPUT"}, append(append([]string{}, tc.match...), "-j", "DROP")...), owner...)
		if len(add) != len(del) {
			t.Fatalf("%s: install has %d args and removal %d -- -D matches by full spec, so it would delete nothing",
				tc.name, len(add), len(del))
		}
		for i := range add {
			if i == 0 {
				continue // -A vs -D, the only difference there may be
			}
			if add[i] != del[i] {
				t.Errorf("%s: arg %d differs (%q install, %q removal) -- the rule would survive its own teardown",
					tc.name, i, add[i], del[i])
			}
		}
		if !strings.Contains(strings.Join(add, " "), "tnl:core42") {
			t.Errorf("%s: the installed rule does not name its owner, so an orphan cannot be swept", tc.name)
		}
	}
}
