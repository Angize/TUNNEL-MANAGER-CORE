//go:build linux

package packet

import (
	"log"
	"os/exec"
	"strings"
)

// Every firewall rule a carrier installs carries the name of the tunnel that installed it.
//
// The rules are removed by Close(), which is correct and enough for an orderly stop. It is not enough
// for anything else: a SIGKILL, a crash or a reboot leaves them behind, and because they go in with -A
// and come out by matching their own exact spec, an orphan is invisible to the next core and simply
// accumulates a duplicate beside it. Measured on the operator's own boxes — a --dport 4500 rule from a
// tunnel that no longer exists, and the same ICMP rule installed twice.
//
// The comment is what makes an orphan attributable: the node sweeps `tnl:<tun>` before it builds a
// tunnel and after it deletes one, so a rule outlives its core by at most one rebuild.
const ruleOwnerPrefix = "tnl:"

// ownerMatch is the match to append to a rule so it names its owner. Empty tun disables it -- a carrier
// built without a device (tests) tags nothing rather than tagging "tnl:".
func ownerMatch(tun string) []string {
	if tun == "" {
		return nil
	}
	return []string{"-m", "comment", "--comment", ruleOwnerPrefix + tun}
}

// iptablesRun is the single door to the firewall. A package var, not a direct exec, because the
// invariant that actually leaked in production is that a rule's REMOVAL must carry the same argv as its
// install -- iptables -D deletes by matching the full spec, so a removal missing one match silently
// removes nothing. A test can only pin that by seeing both argv, which means seeing this call.
var iptablesRun = func(args []string) ([]byte, error) {
	return exec.Command("iptables", args...).CombinedOutput()
}

// runRule executes one iptables rule, retrying WITHOUT the owner comment if the comment match itself is
// what failed. A host with no xt_comment module must still get its anti-leak rule: an untagged rule is
// a cleanup problem, a missing one is a leak.
func runRule(args, owner []string, what string) ([]string, bool) {
	full := append(append([]string(nil), args...), owner...)
	if out, err := iptablesRun(full); err == nil {
		return owner, true
	} else if len(owner) == 0 {
		log.Printf("%s: rule not installed: %v: %s", what, err, strings.TrimSpace(string(out)))
		return nil, false
	}
	if out, err := iptablesRun(args); err != nil {
		log.Printf("%s: rule not installed: %v: %s", what, err, strings.TrimSpace(string(out)))
		return nil, false
	}
	log.Printf("%s: installed WITHOUT an owner comment (no xt_comment on this host) — an orphan here "+
		"cannot be swept by name", what)
	return nil, true
}
