package packet

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
)

// captureLog redirects the standard logger for the duration of fn and returns what was written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	fn()
	return buf.String()
}

// TestFragDoesNotBlameECHItWasNeverToldAbout pins that the two fallback messages state the cause they
// actually know, not the one that is usually true.
//
// Both fired on ANY failure of the hostname search and hard-asserted ECH — and noSplit went further,
// concluding "nothing needs to be [fragmented]: there is no cleartext SNI left for a DPI to read".
// That conclusion only holds if ECH really is on, and fragConn was never told. So the case that
// matters most — the hostname genuinely not matching what the carrier dials with, ECH off, sni_split
// silently doing nothing and the real SNI on the wire in cleartext — produced a log line telling the
// operator they were protected.
//
// Two arms, because a message that is honest in one state and silent in the other proves nothing: with
// ECH the reassuring text must survive, and without it the message must say the SNI is exposed.
func TestFragDoesNotBlameECHItWasNeverToldAbout(t *testing.T) {
	// A ClientHello-shaped buffer that does NOT contain the configured hostname, which is what both
	// branches key on (splitAt returns -1, writeFake's bytes.Index returns -1).
	hello := append([]byte{0x16, 0x03, 0x01, 0x00, 0x40}, bytes.Repeat([]byte{0xAB}, 64)...)

	for _, tc := range []struct {
		name    string
		ech     bool
		want    []string
		notWant []string
	}{
		{
			name: "ECH on — the reassurance is earned",
			ech:  true,
			want: []string{"ECH encrypts it", "no cleartext", "SNI left for a DPI to read"},
		},
		{
			name:    "ECH off — the operator must be told the SNI is exposed",
			ech:     false,
			want:    []string{"ECH is NOT on", "cleartext"},
			notWant: []string{"nothing needs to be", "no cleartext"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()
			defer srv.Close()
			go func() { // drain, so the write does not block on the unbuffered pipe
				buf := make([]byte, 4096)
				for {
					if _, err := srv.Read(buf); err != nil {
						return
					}
				}
			}()

			f := newFragConn(cli, "not-in-this-hello.example", 0, sniSplitMode, 0, tc.ech, nil)
			out := captureLog(func() { _, _ = f.Write(hello) })

			if !strings.Contains(out, "sni_split is on") {
				t.Fatalf("no fallback line was logged at all, so this test proves nothing. got: %q", out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("the message does not mention %q — with ech=%v it must. got: %q", w, tc.ech, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("the message claims %q with ech=%v: it is asserting a protection nothing "+
						"verified, which is exactly the defect. got: %q", w, tc.ech, out)
				}
			}
		})
	}
}
