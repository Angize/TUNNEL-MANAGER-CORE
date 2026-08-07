package tlscover

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The cover borrows a real site: every unauthenticated connection is relayed to dest, so the prober gets
// that site's genuine answer. When dest cannot be reached, proxyToDest can only close — and this file's
// own doc says an instant FIN right after a ClientHello is the exact distinguisher the cover exists to
// deny a censor. So the failure does not merely turn the cover off, it produces the fingerprint the cover
// was added to remove.
//
// It used to do that in complete silence: no startup check, no log on the failing dial, nothing. On an
// Iran-side server pointed at a foreign cover domain that is the ORDINARY case.

// logCapture swaps the standard logger for a buffer. Guarded, because checkDest can run on its own
// goroutine and the race detector is right to care.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	out, flags := log.Writer(), log.Flags()
	log.SetOutput(c)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(out); log.SetFlags(flags) })
	return c
}

// deadAddr returns an address nothing is listening on: a port that was bound and immediately released.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func TestAnUnreachableCoverSiteIsAnnouncedAtStartup(t *testing.T) {
	c := captureLog(t)
	sv := &Server{dest: deadAddr(t)}
	sv.CheckDest()

	got := c.String()
	if !strings.Contains(got, sv.dest) {
		t.Fatalf("startup said nothing about an unreachable cover site. Got %q — an operator who points "+
			"cover_sni at a site this server cannot reach has no way at all to find out", got)
	}
	if !strings.Contains(got, "UNREACHABLE") {
		t.Fatalf("the line does not say the cover is unreachable: %q", got)
	}
}

func TestAReachableCoverSiteSaysSo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	c := captureLog(t)
	sv := &Server{dest: ln.Addr().String()}
	sv.CheckDest()
	if got := c.String(); !strings.Contains(got, sv.dest) {
		t.Fatalf("a working cover is not confirmed either, so the log cannot distinguish "+
			"'checked and fine' from 'never checked'. Got %q", got)
	}
}

// TestALiveRelayFailureIsReportedButRateLimited drives proxyToDest itself. A startup check alone would
// miss the cover going away later, which is the case that actually happens; and an unbounded log would
// hand a censor scanning the port a log amplifier, so it is one line a minute.
func TestALiveRelayFailureIsReportedButRateLimited(t *testing.T) {
	c := captureLog(t)
	sv := &Server{
		dest:  deadAddr(t),
		relay: make(chan struct{}, maxRelays),
		queue: make(chan struct{}, maxWaiting),
		idle:  relayIdle,
		seen:  map[[32]byte]int64{},
	}

	for i := 0; i < 5; i++ {
		cli, srv := net.Pipe()
		go func() { cli.Read(make([]byte, 1)); cli.Close() }()
		sv.proxyToDest(srv, []byte("hello"))
	}
	// proxyToDest relays on its own goroutine; give the dials time to fail.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(c.String(), sv.dest) {
		time.Sleep(20 * time.Millisecond)
	}

	got := c.String()
	if !strings.Contains(got, sv.dest) {
		t.Fatalf("five probes were closed on the spot instead of relayed and nothing was logged. Got %q", got)
	}
	if n := strings.Count(got, "cannot reach"); n != 1 {
		t.Fatalf("%d lines for five failures in the same second — a port scan would turn this into its "+
			"own log amplifier. Got %q", n, got)
	}
}
