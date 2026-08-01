package packet

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// capConn is a net.Conn that records what was written and exposes chosen addresses, so the SNI
// fragmentation paths can be driven without a real socket.
type capConn struct {
	buf        bytes.Buffer
	local, rem net.Addr
}

func (c *capConn) Read([]byte) (int, error)         { return 0, nil }
func (c *capConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *capConn) Close() error                     { return nil }
func (c *capConn) LocalAddr() net.Addr              { return c.local }
func (c *capConn) RemoteAddr() net.Addr             { return c.rem }
func (c *capConn) SetDeadline(time.Time) error      { return nil }
func (c *capConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capConn) SetWriteDeadline(time.Time) error { return nil }

func fragLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// hello builds a stand-in ClientHello carrying host in cleartext (or not, when host is empty —
// which is what ECH looks like from this layer).
func hello(host string) []byte {
	var b bytes.Buffer
	b.WriteString("\x16\x03\x01padding-before-the-name-")
	b.WriteString(host)
	b.WriteString("-padding-after-the-name")
	return b.Bytes()
}

// TestFakeModeSaysWhenItCouldNotRun is the regression test for sni_mode=fake degrading in silence.
//
// In user terms: the operator picks «fake», the mode that is the ONLY one which beats a DPI
// reassembling the TCP stream, and the panel keeps showing it. Every one of writeFake's six
// bail-outs handed off to disorder without a word — so a container missing CAP_NET_ADMIN, an IPv6
// edge, or a TLS conn with no raw fd left the tunnel running a materially weaker defence while every
// dashboard said otherwise.
func TestFakeModeSaysWhenItCouldNotRun(t *testing.T) {
	buf := fragLog(t)
	// A conn whose addresses are not TCP: writeFake's very first bail-out.
	c := &capConn{local: strAddr("local"), rem: strAddr("remote")}
	f := newFragConn(c, "example.com", 0, sniFakeMode, 0, false, nil)
	if _, err := f.Write(hello("example.com")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "fell back to disorder") {
		t.Fatalf("fake degraded to disorder in silence; log was %q — the operator keeps seeing the "+
			"strongest mode on a tunnel that is not running it", out)
	}

	// Once per connection: a second write must not repeat it.
	buf.Reset()
	if _, err := f.Write(hello("example.com")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("the fallback repeated on a later write: %q", buf.String())
	}
}

// TestFakeModeRefusesAByteIdenticalDecoy pins the ECH case. With the hostname encrypted there is
// nothing in the ClientHello to overwrite, so the "decoy" is a byte-for-byte copy of the real one.
// Injecting that at the same sequence with a corrupt checksum gives a reassembling DPI exactly the
// SNI it would have seen anyway — zero benefit — while a duplicate segment carrying a bad checksum
// is itself a signature. It is reachable whenever ECH is on AND split_pos is set, because splitAt
// returns f.pos before it ever looks for the hostname.
func TestFakeModeRefusesAByteIdenticalDecoy(t *testing.T) {
	buf := fragLog(t)
	// Real TCP addresses, so the earlier bail-outs are passed and the decoy branch is the one reached.
	c := &capConn{
		local: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
		rem:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443},
	}
	// An explicit split_pos, so splitAt does not need the hostname — and a payload that does NOT
	// contain it, which is what ECH leaves behind. ech=true because that is the situation described:
	// the refusal is right either way, but only this arm may claim there is nothing left to hide.
	f := newFragConn(c, "example.com", 12, sniFakeMode, 0, true, nil)
	p := hello("") // no cleartext hostname anywhere in the buffer
	if bytes.Contains(p, []byte("example.com")) {
		t.Fatal("the fixture must not carry the hostname in cleartext")
	}
	if _, err := f.Write(p); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "byte-identical") {
		t.Fatalf("a decoy identical to the real ClientHello was not refused; log was %q — injecting it "+
			"adds a signature and hides nothing", got)
	}
	if got := c.buf.Bytes(); !bytes.Equal(got, p) {
		t.Fatalf("the real ClientHello must still go out whole (as two segments in order): got %d bytes, want %d",
			len(got), len(p))
	}
}

// TestSNISplitSaysWhenNothingIsSplit is the regression test for E12: under ECH the cleartext search
// finds nothing, splitAt returns 0, the ClientHello goes out whole — and the config, the panel and
// the startup log all still say sni_split is on. Correct behaviour (there is no cleartext SNI left
// to straddle a boundary), but it was completely silent, so an operator running ECH plus sni_split
// believed both were active when only one was.
func TestSNISplitSaysWhenNothingIsSplit(t *testing.T) {
	for _, tc := range []struct {
		name, host, want string
		ech              bool
	}{
		// ech must be TRUE here: this case IS the ECH one, and the message it asserts is the one that
		// concludes there is nothing left to protect. Passing false would make it assert that
		// conclusion for a dial with no ECH at all — the defect this signature exists to prevent.
		{"ech hides the hostname", "example.com", "not in the ClientHello in cleartext", true},
		{"carrier dials with no SNI", "", "no SNI", false},
	} {
		buf := fragLog(t)
		c := &capConn{local: strAddr("l"), rem: strAddr("r")}
		f := newFragConn(c, tc.host, 0, sniSplitMode, 0, tc.ech, nil)
		p := hello("")
		if _, err := f.Write(p); err != nil {
			t.Fatal(err)
		}
		if got := buf.String(); !strings.Contains(got, tc.want) {
			t.Fatalf("%s: nothing was split and nothing was said; log was %q", tc.name, got)
		}
		if !bytes.Equal(c.buf.Bytes(), p) {
			t.Fatalf("%s: the ClientHello must still go out whole and unmodified", tc.name)
		}
	}

	// An out-of-range split_pos is its own cause and must name itself, not blame ECH.
	buf := fragLog(t)
	c := &capConn{local: strAddr("l"), rem: strAddr("r")}
	p := hello("example.com")
	f := newFragConn(c, "example.com", len(p)+50, sniSplitMode, 0, false, nil)
	if _, err := f.Write(p); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "outside the") {
		t.Fatalf("an out-of-range split_pos must say so, got %q", got)
	}

	// And the case that WORKS must stay silent, or the line becomes noise on every healthy tunnel.
	buf = fragLog(t)
	c = &capConn{local: strAddr("l"), rem: strAddr("r")}
	f = newFragConn(c, "example.com", 0, sniSplitMode, 0, false, nil)
	if _, err := f.Write(hello("example.com")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("a ClientHello that WAS split reported a failure: %q", buf.String())
	}
}
