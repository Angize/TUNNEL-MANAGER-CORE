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

// ownerLabel is what a log line may claim about a rule that is already installed: the owner it really
// carries, or "none" when runRule had to drop the comment. Naming an owner the rule does not have sends
// the operator sweeping for a tag that is not there.
func ownerLabel(used []string, tun string) string {
	if len(used) == 0 {
		return "none"
	}
	return ruleOwnerPrefix + tun
}

// checkArgs turns an install argv into the -C query that asks whether that exact rule is already in
// the chain. nil when the argv installs nothing (so the caller skips the question).
func checkArgs(args []string) []string {
	c := append([]string(nil), args...)
	for i, a := range c {
		if a == "-I" || a == "-A" {
			c[i] = "-C"
			return c
		}
	}
	return nil
}

// alreadyIn reports whether this exact rule is in the chain already, and with which owner. Installs go
// in blind, so without this a re-scope onto a destination whose earlier rule was never removed adds a
// SECOND identical rule beside it — and the removal we hand back deletes one, forever leaving one more.
// Both spellings are asked because runRule may have had to drop the comment when it went in.
func alreadyIn(args, owner []string) ([]string, bool) {
	chk := checkArgs(args)
	if chk == nil {
		return nil, false
	}
	if _, err := iptablesRun(append(append([]string(nil), chk...), owner...)); err == nil {
		return owner, true
	}
	if len(owner) > 0 {
		if _, err := iptablesRun(chk); err == nil {
			return nil, true
		}
	}
	return nil, false
}

// delRule removes one rule, and says so when it does not go. Installs log and removals did not, so a
// rule that survived its own teardown was invisible — right up until the duplicate it caused.
func delRule(args []string, what string) {
	if out, err := iptablesRun(args); err != nil {
		log.Printf("%s: rule NOT removed (%v: %s) — it stays on the host until the node's %s sweep",
			what, err, strings.TrimSpace(string(out)), ruleOwnerPrefix+"<tun>")
	}
}

// commentRefused reports whether iptables turned the rule down because of the comment match. The two
// argv runRule can send differ by nothing else, so retrying without the comment is only defensible
// when that is what failed: on any other error the retry sends a command that already failed for a
// reason still present, and if it wins the race the second time the rule goes in UNTAGGED — invisible
// to the node's tnl:<tun> sweep, and reported as "no xt_comment on this host", which was never true.
func commentRefused(out []byte) bool {
	s := strings.ToLower(string(out))
	for _, m := range []string{"comment", "no chain/target/match by that name", "couldn't load match"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// runRule executes one iptables rule. A host with no xt_comment module must still get its anti-leak
// rule -- an untagged rule is a cleanup problem, a missing one is a leak -- so the comment is dropped
// and the rule retried, but only when the comment is what iptables objected to. Every failure is
// logged with what iptables actually said; the first attempt's output used to be thrown away, so the
// real cause was never visible.
func runRule(args, owner []string, what string) ([]string, bool) {
	if own, ok := alreadyIn(args, owner); ok {
		return own, true // a removal that failed earlier left it there; do not add a twin
	}
	full := append(append([]string(nil), args...), owner...)
	out, err := iptablesRun(full)
	if err == nil {
		return owner, true
	}
	first := strings.TrimSpace(string(out))
	log.Printf("%s: rule not installed: %v: %s", what, err, first)
	if len(owner) == 0 || !commentRefused(out) {
		return nil, false
	}
	if out, err := iptablesRun(args); err != nil {
		log.Printf("%s: nor without its owner comment: %v: %s", what, err, strings.TrimSpace(string(out)))
		return nil, false
	}
	log.Printf("%s: installed WITHOUT an owner comment, because iptables refused the comment match (%s) — "+
		"an orphan here cannot be swept by name", what, first)
	return nil, true
}
