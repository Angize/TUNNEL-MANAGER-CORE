package packet

import (
	"bytes"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

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

func hello(host string) []byte {
	var b bytes.Buffer
	b.WriteString("\x16\x03\x01padding-before-the-name-")
	b.WriteString(host)
	b.WriteString("-padding-after-the-name")
	return b.Bytes()
}

func TestFakeModeSaysWhenItCouldNotRun(t *testing.T) {
	buf := fragLog(t)

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

	buf.Reset()
	if _, err := f.Write(hello("example.com")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("the fallback repeated on a later write: %q", buf.String())
	}
}

func TestFakeModeRefusesAByteIdenticalDecoy(t *testing.T) {
	buf := fragLog(t)

	c := &capConn{
		local: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 40000},
		rem:   &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443},
	}

	f := newFragConn(c, "example.com", 12, sniFakeMode, 0, true, nil)
	p := hello("")
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

func TestSNISplitSaysWhenNothingIsSplit(t *testing.T) {
	for _, tc := range []struct {
		name, host, want string
		ech              bool
	}{

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
