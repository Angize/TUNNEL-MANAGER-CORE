//go:build linux

package packet

import "testing"

// sourceMode in main.go asks the carrier, at runtime, whether it can fix a source: it type-asserts
// interface{ SetSourceIP(string) } and warns the operator when the assertion fails. A carrier that
// loses that method does not fail to compile -- bind_ip just stops working on it, and the only sign
// is a warning line in a log nobody is reading at the time.
//
// The old shape had a second branch that handed a bare bind_ip to SetSourcePool as a one-entry pool.
// That branch is gone, so this assertion is now the only thing standing between bind_ip and silence.
func TestEveryCarrierCanFixItsSource(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
	}{
		{"udp", &UDP{}},
		{"raw", &Raw{}},
		{"tcp, ws, http and grpc", &TCP{}},
	} {
		if _, ok := c.v.(interface{ SetSourceIP(string) }); !ok {
			t.Errorf("%s cannot fix a source IP any more: sourceMode will report it unsupported and "+
				"bind_ip becomes a no-op on it", c.name)
		}
	}
}
