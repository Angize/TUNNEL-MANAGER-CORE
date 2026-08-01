package packet

import (
	"fmt"
	"os"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The uTLS ClientHello parrot and the advertised HTTP User-Agent must name the SAME Chrome major. A real
// browser's JA3/JA4 and its User-Agent always agree; a disagreement here — a uTLS bump that moved
// HelloChrome_Auto while the UA const stayed, or the reverse — is a cheap, high-confidence fingerprint.
// Wiring the two together in a test fails the build the moment they drift.
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

// TestAcceptEncodingMatchesUAMajor ties the advertised Accept-Encoding to the Chrome major the UA and the
// uTLS parrot both name, the way TestUserAgentMatchesTLSParrot ties the UA to the parrot. Chrome has
// offered zstd by default since 123, and the ws carrier hand-writes its header block rather than deriving
// it from the parrot — so without this guard the next bump moves the UA and leaves the list behind.
func TestAcceptEncodingMatchesUAMajor(t *testing.T) {
	major := 0
	if _, err := fmt.Sscanf(utls.HelloChrome_Auto.Version, "%d", &major); err != nil || major == 0 {
		t.Fatalf("cannot read the uTLS parrot's Chrome major from %q", utls.HelloChrome_Auto.Version)
	}
	// The identity has to be internally consistent before the version rule means anything.
	for _, tok := range []string{"gzip", "deflate", "br"} {
		if !strings.Contains(chromeAcceptEncoding, tok) {
			t.Errorf("chromeAcceptEncoding %q is missing %q, which every Chrome sends", chromeAcceptEncoding, tok)
		}
	}
	if major >= 123 && !strings.Contains(chromeAcceptEncoding, "zstd") {
		t.Errorf("we claim Chrome %d but advertise %q — zstd has been in Chrome's default Accept-Encoding since 123",
			major, chromeAcceptEncoding)
	}
	if major < 123 && strings.Contains(chromeAcceptEncoding, "zstd") {
		t.Errorf("we claim Chrome %d but advertise zstd, which it did not send yet: %q", major, chromeAcceptEncoding)
	}
}

// TestWSUpgradeUsesTheSharedEncoding guards the wiring, not just the constant: the ws upgrade must
// USE chromeAcceptEncoding. A correct constant next to a hard-coded header would pass the test above
// and still put the stale list on the wire — the shape of the original defect.
func TestWSUpgradeUsesTheSharedEncoding(t *testing.T) {
	src, err := os.ReadFile("wsconn.go")
	if err != nil {
		t.Fatalf("read wsconn.go: %v", err)
	}
	s := string(src)
	if !strings.Contains(s, `"Accept-Encoding: " + chromeAcceptEncoding`) {
		t.Error("the ws upgrade does not build Accept-Encoding from chromeAcceptEncoding")
	}
	if strings.Contains(s, `"Accept-Encoding: gzip`) {
		t.Error("the ws upgrade still hard-codes an Accept-Encoding list")
	}
}
