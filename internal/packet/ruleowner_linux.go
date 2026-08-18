//go:build linux

package packet

import (
	"log"
	"os/exec"
	"strings"
)

const ruleOwnerPrefix = "tnl:"

func ownerMatch(tun string) []string {
	if tun == "" {
		return nil
	}
	return []string{"-m", "comment", "--comment", ruleOwnerPrefix + tun}
}

var iptablesRun = func(args []string) ([]byte, error) {
	return exec.Command("iptables", args...).CombinedOutput()
}

func ownerLabel(used []string, tun string) string {
	if len(used) == 0 {
		return "none"
	}
	return ruleOwnerPrefix + tun
}

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

func delRule(args []string, what string) {
	if out, err := iptablesRun(args); err != nil {
		log.Printf("%s: rule NOT removed (%v: %s) — it stays on the host until the node's %s sweep",
			what, err, strings.TrimSpace(string(out)), ruleOwnerPrefix+"<tun>")
	}
}

func commentRefused(out []byte) bool {
	s := strings.ToLower(string(out))
	for _, m := range []string{"comment", "no chain/target/match by that name", "couldn't load match"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func runRule(args, owner []string, what string) ([]string, bool) {
	if own, ok := alreadyIn(args, owner); ok {
		return own, true
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
