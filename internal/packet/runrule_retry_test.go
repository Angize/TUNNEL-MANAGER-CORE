//go:build linux

package packet

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
)

// runRule may drop the owner comment and try again, and that is a real need: a host with no xt_comment
// must still get its anti-leak rule, because an untagged rule is a cleanup problem while a missing one
// is a leak. What it may NOT do is retry on an error that has nothing to do with the comment.
//
// It did. The only condition was "was an owner asked for", so a rule that lost the race for the xtables
// lock was retried a millisecond later, and if that one won it went in UNTAGGED — invisible to the
// node's tnl:<tun> sweep — under a log line claiming there is no xt_comment on this host, which was
// never established. The first attempt's output was dropped, so the real cause was never printed.
func TestRunRuleOnlyDropsTheOwnerCommentWhenTheCommentIsWhatFailed(t *testing.T) {
	const lockBusy = "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?"
	const noModule = "iptables v1.8.11 (nf_tables): unknown option \"--comment\""
	const noMatch = "iptables: No chain/target/match by that name."

	for _, tc := range []struct {
		name       string
		firstOut   string // what iptables says to the argv carrying the comment
		wantRetry  bool   // ...and whether a second, bare attempt is defensible
		wantOK     bool
		wantLogged string
	}{
		{"the xtables lock was busy", lockBusy, false, false, "xtables lock"},
		{"no xt_comment module", noModule, true, true, "refused the comment match"},
		{"the match could not be loaded", noMatch, true, true, "refused the comment match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent [][]string
			restore := iptablesRun
			iptablesRun = func(a []string) ([]byte, error) {
				// -C is the "is it there already" probe, not an install attempt: answer no, and leave it
				// out of the count, which is about how many times we tried to PUT the rule in.
				if indexOfArg(a, "-C") >= 0 {
					return nil, errRuleAbsent
				}
				sent = append(sent, append([]string(nil), a...))
				if strings.Contains(strings.Join(a, " "), "-m comment") {
					return []byte(tc.firstOut), errors.New("exit status 4")
				}
				return nil, nil // the bare rule always goes in, so a retry is always OBSERVABLE
			}
			defer func() { iptablesRun = restore }()

			var logged bytes.Buffer
			log.SetOutput(&logged)
			defer log.SetOutput(os.Stderr)

			own, ok := runRule([]string{"-I", "OUTPUT", "-d", "10.0.0.1", "-j", "DROP"},
				ownerMatch("core42"), "raw: anti-leak")

			if len(sent) != 1 && !tc.wantRetry {
				t.Errorf("iptables was called %d times; the comment was not the problem, so the bare "+
					"retry must not happen — it puts an unsweepable rule on the host: %v", len(sent), sent)
			}
			if tc.wantRetry && len(sent) != 2 {
				t.Errorf("iptables was called %d times, want 2 (tagged, then bare)", len(sent))
			}
			if ok != tc.wantOK {
				t.Errorf("runRule reported ok=%v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && len(own) != 0 {
				t.Errorf("a rule that went in untagged reported owner %v — the log would then name a tag "+
					"the rule does not carry", own)
			}
			// Whatever happened, iptables' own words have to reach the log: that is the only place the
			// operator can learn WHY, and the first attempt's output used to be discarded entirely.
			if !strings.Contains(logged.String(), tc.wantLogged) {
				t.Errorf("the log does not carry %q; it said %q", tc.wantLogged, logged.String())
			}
			if !strings.Contains(logged.String(), tc.firstOut) {
				t.Errorf("the log never printed what iptables actually said (%q); it said %q",
					tc.firstOut, logged.String())
			}
			if !tc.wantOK && strings.Contains(logged.String(), "no xt_comment") {
				t.Errorf("the log diagnosed a missing xt_comment that was never established: %q", logged.String())
			}
		})
	}

	// The other direction: a carrier with no tun name asks for no owner at all, so there is nothing to
	// drop and nothing to retry.
	t.Run("an untagged carrier makes exactly one attempt", func(t *testing.T) {
		var sent int
		restore := iptablesRun
		iptablesRun = func(a []string) ([]byte, error) {
			if indexOfArg(a, "-C") >= 0 {
				return nil, errRuleAbsent
			}
			sent++
			return []byte(lockBusy), errors.New("exit status 4")
		}
		defer func() { iptablesRun = restore }()
		log.SetOutput(&bytes.Buffer{})
		defer log.SetOutput(os.Stderr)

		if _, ok := runRule([]string{"-I", "OUTPUT", "-j", "DROP"}, ownerMatch(""), "raw: anti-leak"); ok {
			t.Error("a failed install reported success")
		}
		if sent != 1 {
			t.Errorf("iptables was called %d times, want 1", sent)
		}
	})
}
