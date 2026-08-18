package packet

import (
	"fmt"
	"os"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestUserAgentMatchesTLSParrot(t *testing.T) {
	parrot := utls.HelloChrome_Auto.Version
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

func TestAcceptEncodingMatchesUAMajor(t *testing.T) {
	major := 0
	if _, err := fmt.Sscanf(utls.HelloChrome_Auto.Version, "%d", &major); err != nil || major == 0 {
		t.Fatalf("cannot read the uTLS parrot's Chrome major from %q", utls.HelloChrome_Auto.Version)
	}

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
