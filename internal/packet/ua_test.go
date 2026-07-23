package packet

import (
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The uTLS ClientHello parrot and the advertised HTTP User-Agent must name the SAME Chrome major. A
// real browser's JA3/JA4 (derived from its TLS ClientHello) and its User-Agent always agree; if they
// disagree here — e.g. a uTLS bump moved HelloChrome_Auto but the UA const was left behind, or vice
// versa — that mismatch is a cheap, high-confidence fingerprint. Wiring the two together in a test
// fails the build the moment they drift, so the ws/xhttp carriers can never ship a skewed pair.
func TestUserAgentMatchesTLSParrot(t *testing.T) {
	parrot := utls.HelloChrome_Auto.Version // e.g. "133"
	if parrot == "" {
		t.Fatal("utls.HelloChrome_Auto has no Version — cannot verify UA/JA3 consistency")
	}
	const tok = "Chrome/"
	i := strings.Index(chromeUA, tok)
	if i < 0 {
		t.Fatalf("chromeUA %q has no %q token", chromeUA, tok)
	}
	rest := chromeUA[i+len(tok):]
	j := strings.IndexByte(rest, '.')
	if j < 0 {
		t.Fatalf("chromeUA %q Chrome version has no dot separator", chromeUA)
	}
	if uaMajor := rest[:j]; uaMajor != parrot {
		t.Fatalf("JA3<->UA skew: uTLS parrot is Chrome %q but the User-Agent advertises Chrome %q — update chromeUA to match utls.HelloChrome_Auto", parrot, uaMajor)
	}
}
