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
	// The signature includes the bool: a carrier is the only thing that knows whether it will really
	// ENFORCE the value, and main prints "self-heal deadline set to Ns" on the strength of that answer.
	// A carrier that dropped back to the void-returning shape would fail this assertion and take the
	// setting silently inert again — the exact failure this test exists for.
	for _, c := range []any{&TCP{}, &UDP{}, &Raw{}, &Flux{}, &DNS{}} {
		if _, ok := c.(interface{ SetDeadAfter(int) bool }); !ok {
			t.Fatalf("%T does not implement SetDeadAfter(int) bool — dead_after_secs is silently inert on it", c)
		}
	}
}
