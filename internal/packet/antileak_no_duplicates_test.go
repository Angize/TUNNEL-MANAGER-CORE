//go:build linux

package packet

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"testing"
)

// A rule that survived its own teardown must not get a twin.
//
// Removals ran as `_, _ = iptablesRun(...)`: no check, no log. Installs go in blind, so once one
// removal failed — a contended xtables lock is enough — the next scope onto that same destination
// added a SECOND identical rule, and the removal handed back deletes one. Every round trip through
// that destination leaves one more, for the life of the process, and nobody is told: the install
// logs, the removal did not.
func TestAnAntiLeakRuleIsNeverInstalledTwice(t *testing.T) {
	t.Run("a re-scope onto a rule that is still there adds nothing", func(t *testing.T) {
		fake := &fakeIptables{}
		defer fake.install()()

		rm := addRawDrop(leakPeer, "udp", "core42", 0, true, false, false)
		if rm == nil || fake.total() != 1 {
			t.Fatalf("the first install put %d rule(s) on the host: %v", fake.total(), fake.snapshot())
		}
		fake.setFailDel(true) // the removal does not go through
		rm()
		if fake.total() != 1 {
			t.Fatalf("a failed -D removed the rule anyway: %v", fake.snapshot())
		}
		fake.setFailDel(false)

		rm2 := addRawDrop(leakPeer, "udp", "core42", 0, true, false, false)
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

	// The same thing through the real re-scoping path, where it actually happens: rotate away, fail to
	// remove, rotate back. flux carries one rule per pool port, so it multiplies whatever this gets wrong.
	t.Run("a rotation back onto a stale rule, through the antiLeaker", func(t *testing.T) {
		const first, second = "203.0.113.10", "203.0.113.20"
		for _, carrier := range []string{"udp", "stun"} {
			fake := &fakeIptables{}
			undo := fake.install()

			closeCh := make(chan struct{})
			var leak antiLeaker
			leak.init(closeCh, func(peer net.IP) func() { return addFluxDrop(peer, carrier, "core42") })

			leak.scope(net.ParseIP(first).To4())
			if fake.total() == 0 {
				t.Fatalf("flux/%s installed nothing", carrier)
			}
			fake.setFailDel(true)
			leak.scope(net.ParseIP(second).To4()) // rotate away; removing `first` fails
			fake.setFailDel(false)
			leak.scope(net.ParseIP(first).To4()) // ...and back

			if d := fake.dups(); d != 0 {
				t.Errorf("flux/%s: %d duplicate rule(s) on the host after one failed removal: %v",
					carrier, d, fake.snapshot())
			}
			close(closeCh)
			leak.teardown()
			undo()
		}
	})

	// A host with no xt_comment gets its rule untagged, so the "is it already there" probe has to ask
	// for the untagged spelling too. Asking only for the tagged one never matches, and the duplicate
	// comes back on exactly the hosts that can least afford an unattributable rule.
	t.Run("a host with no xt_comment does not collect duplicates either", func(t *testing.T) {
		fake := &fakeIptables{noComment: true}
		defer fake.install()()

		rm := addRawDrop(leakPeer, "udp", "core42", 0, true, false, false)
		if rm == nil || fake.total() != 1 {
			t.Fatalf("the untagged fallback put %d rule(s) on the host: %v", fake.total(), fake.snapshot())
		}
		fake.setFailDel(true)
		rm()
		fake.setFailDel(false)
		addRawDrop(leakPeer, "udp", "core42", 0, true, false, false)
		if n, d := fake.total(), fake.dups(); n != 1 || d != 0 {
			t.Errorf("%d rule(s), %d of them copies: %v", n, d, fake.snapshot())
		}
	})

	// And it has to be visible. A removal that fails is the moment the host starts carrying something
	// nobody is tracking.
	t.Run("a failed removal is reported", func(t *testing.T) {
		fake := &fakeIptables{}
		defer fake.install()()
		var logged bytes.Buffer
		log.SetOutput(&logged)
		defer log.SetOutput(os.Stderr)

		rm := addRawDrop(leakPeer, "tcp", "core42", 0, true, false, false)
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
