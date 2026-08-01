package packet

import (
	"strings"
	"testing"
)

// validHostname reports whether s is a syntactically well-formed DNS name: no leading, trailing or
// doubled dot, every label 1..63 bytes, and only characters a hostname may carry.
func validHostname(s string) (bool, string) {
	if s == "" {
		return false, "empty"
	}
	if strings.HasPrefix(s, ".") {
		return false, "leading dot"
	}
	if strings.HasSuffix(s, ".") {
		return false, "trailing dot"
	}
	for _, lbl := range strings.Split(s, ".") {
		if lbl == "" {
			return false, "empty label (doubled dot)"
		}
		if len(lbl) > 63 {
			return false, "label longer than 63 bytes"
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false, "label starts or ends with a hyphen"
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false, "illegal character in a label"
			}
		}
	}
	return true, ""
}

// TestDecoySNIIsANameThatCouldExist is the point of the decoy, stated as a spec. decoySNI must return
// EXACTLY n bytes, because the fake ClientHello's SNI length field has to stay valid and n is dictated by
// the real hostname. Every length must still yield a well-formed hostname — a chopped or doubled constant
// is a structurally impossible SNI, an anomaly worth flagging, which is the opposite of a decoy's point.
func TestDecoySNIIsANameThatCouldExist(t *testing.T) {
	shortest := len(decoyApexes[0])
	for _, a := range decoyApexes {
		if len(a) < shortest {
			shortest = len(a)
		}
	}
	for n := 1; n <= 253; n++ {
		got := string(decoySNI(n))
		if len(got) != n {
			t.Fatalf("decoySNI(%d) is %d bytes — the SNI length field would be wrong", n, len(got))
		}
		if ok, why := validHostname(got); !ok {
			t.Errorf("decoySNI(%d) = %q is not a valid hostname: %s", n, got, why)
			continue
		}
		if n < shortest {
			continue // too short to carry any real domain; a bare label is the best available
		}
		ends := false
		for _, a := range decoyApexes {
			if got == a || strings.HasSuffix(got, "."+a) {
				ends = true
				break
			}
		}
		if !ends {
			t.Errorf("decoySNI(%d) = %q does not end in a real domain — it stops mid-name", n, got)
		}
	}
}

// registrable returns the last two labels of s — near enough to "the domain someone blocks".
func registrable(s string) string {
	p := strings.Split(s, ".")
	if len(p) < 2 {
		return s
	}
	return p[len(p)-2] + "." + p[len(p)-1]
}

// TestDecoySNINeverLeaksTheRealHost keeps the original guarantee: the decoy exists to REPLACE the real
// SNI, so the real name must not survive inside it and must not share the domain being hidden — a decoy
// naming our own registrable domain carries the exact verdict we are trying to escape. Substring
// containment is checked only for realistic hostnames, since a 3-byte name matches by coincidence.
func TestDecoySNINeverLeaksTheRealHost(t *testing.T) {
	for _, host := range []string{"cdn.spacefly.ir", "very-long-fronting-host.example.co.uk", "edge.arvanstatic.ir"} {
		for n := 1; n <= 253; n++ {
			got := string(decoySNI(n))
			if strings.Contains(got, host) {
				t.Fatalf("decoySNI(%d) contains the real host %q", n, host)
			}
			if len(got) > 3 && registrable(got) == registrable(host) {
				t.Fatalf("decoySNI(%d) = %q shares the registrable domain of %q — it inherits the verdict we are escaping", n, got, host)
			}
		}
	}
}
