//go:build linux

package packet

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestAnAntiLeakRuleIsNeverInstalledTwice(t *testing.T) {
	t.Run("a re-scope onto a rule that is still there adds nothing", func(t *testing.T) {
		fake := &fakeIptables{}
		defer fake.install()()

		rm, _ := addRawDrop(leakPeer, "udp", "core42", 0, true, false)
		if rm == nil || fake.total() != 1 {
			t.Fatalf("the first install put %d rule(s) on the host: %v", fake.total(), fake.snapshot())
		}
		fake.setFailDel(true)
		rm()
		if fake.total() != 1 {
			t.Fatalf("a failed -D removed the rule anyway: %v", fake.snapshot())
		}
		fake.setFailDel(false)

		rm2, _ := addRawDrop(leakPeer, "udp", "core42", 0, true, false)
		if n, d := fake.total(), fake.dups(); n != 1 || d != 0 {
			t.Errorf("re-scoping onto a destination whose rule was never removed left %d rule(s), %d of them copies: %v",
				n, d, fake.snapshot())
		}
		if rm2 == nil {
			t.Fatal("no removal handed back for a rule that is in the chain — it could never be taken out")
		}
		rm2()
		if fake.total() != 0 {
			t.Errorf("the rule outlived its teardown: %v", fake.snapshot())
		}
	})

	t.Run("a host with no xt_comment does not collect duplicates either", func(t *testing.T) {
		fake := &fakeIptables{noComment: true}
		defer fake.install()()

		rm, _ := addRawDrop(leakPeer, "udp", "core42", 0, true, false)
		if rm == nil || fake.total() != 1 {
			t.Fatalf("the untagged fallback put %d rule(s) on the host: %v", fake.total(), fake.snapshot())
		}
		fake.setFailDel(true)
		rm()
		fake.setFailDel(false)
		_, _ = addRawDrop(leakPeer, "udp", "core42", 0, true, false)
		if n, d := fake.total(), fake.dups(); n != 1 || d != 0 {
			t.Errorf("%d rule(s), %d of them copies: %v", n, d, fake.snapshot())
		}
	})

	t.Run("a failed removal is reported", func(t *testing.T) {
		fake := &fakeIptables{}
		defer fake.install()()
		var logged bytes.Buffer
		log.SetOutput(&logged)
		defer log.SetOutput(os.Stderr)

		rm, _ := addRawDrop(leakPeer, "tcp", "core42", 0, true, false)
		if rm == nil {
			t.Fatal("nothing installed")
		}
		fake.setFailDel(true)
		logged.Reset()
		rm()
		if !strings.Contains(logged.String(), "NOT removed") {
			t.Errorf("a failed removal said nothing; the log carried %q", logged.String())
		}
	})
}
