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

func TestRunRuleOnlyDropsTheOwnerCommentWhenTheCommentIsWhatFailed(t *testing.T) {
	const lockBusy = "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?"
	const noModule = "iptables v1.8.11 (nf_tables): unknown option \"--comment\""
	const noMatch = "iptables: No chain/target/match by that name."

	for _, tc := range []struct {
		name       string
		firstOut   string
		wantRetry  bool
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

				if indexOfArg(a, "-C") >= 0 {
					return nil, errRuleAbsent
				}
				sent = append(sent, append([]string(nil), a...))
				if strings.Contains(strings.Join(a, " "), "-m comment") {
					return []byte(tc.firstOut), errors.New("exit status 4")
				}
				return nil, nil
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
