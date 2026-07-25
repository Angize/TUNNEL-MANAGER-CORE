//go:build linux

package packet

import "testing"

// TestEveryClientCarrierAcceptsDeadAfter guards the ONLY channel through which the operator's
// fleet-wide dead_after_secs reaches a carrier: main.go probes for this method with a type assertion.
//
// A carrier that simply lacks it fails the assertion and the setting is silently inert — and because
// the "self-heal deadline set to Ns" log line lives INSIDE the successful branch, the operator gets no
// confirmation and no warning either. That is exactly what happened to *DNS, whose method set carried
// no SetDeadAfter while main.go's comment asserted "Every carrier implements it".
//
// A compile-time check would not catch this: the carriers are only ever held as the carrier interface,
// so a missing method is invisible until that runtime assertion quietly fails.
func TestEveryClientCarrierAcceptsDeadAfter(t *testing.T) {
	for _, c := range []any{&TCP{}, &UDP{}, &Raw{}, &Flux{}, &DNS{}} {
		if _, ok := c.(interface{ SetDeadAfter(int) }); !ok {
			t.Fatalf("%T does not implement SetDeadAfter — dead_after_secs is silently inert on it", c)
		}
	}
}
