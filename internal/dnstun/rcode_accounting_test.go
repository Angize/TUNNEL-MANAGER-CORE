package dnstun

import (
	"bytes"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// swapLogOutput points the process logger at sink (timestamps off so a Contains assertion is stable)
// and returns the restore func.
func swapLogOutput(sink *syncBuf) func() {
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetFlags(0)
	log.SetOutput(sink)
	return func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) }
}

// syncBuf is a log sink several goroutines may write to at once.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// rejectResponse packs an answer-less response carrying an RCode — what a rate-limiting, refusing or
// non-recursing resolver really sends: Response set, the id echoed, no TXT records.
func rejectResponse(id uint16, qn dnsmessage.Name, rc dnsmessage.RCode) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true, RCode: rc},
		Questions: []dnsmessage.Question{{
			Name: qn, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET,
		}},
	}
	b, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return b
}

// rcodeResolver is a fake recursive resolver that answers TXT queries with a real payload until the
// test flips `rejecting`, and rejects every query with rc after that. The flip is a switch rather than
// a count so the two phases are separable: with a count, loopback answers all 16 in-flight queries fast
// enough that the window could open and collapse between two polls of the test.
func rcodeResolver(t *testing.T, rejecting *atomic.Bool, rc dnsmessage.RCode) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake resolver: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			id, qname, qtype, ok := parseQuery(buf[:n])
			if !ok || qtype != dnsmessage.TypeTXT {
				continue
			}
			qn, nerr := dnsmessage.NewName(qname)
			if nerr != nil {
				continue
			}
			if rejecting.Load() {
				_, _ = pc.WriteToUDP(rejectResponse(id, qn, rc), addr)
				continue
			}
			resp, berr := buildResponse(id, qn, dnsmessage.TypeTXT,
				[]dnsmessage.Resource{txtResource(qn, []string{"\x01payload"})}, nil)
			if berr == nil {
				_, _ = pc.WriteToUDP(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// A resolver that REJECTS every query must be said out loud and must be counted. parseResponseTXT has an
// RCode check so a rejection stops looking like a healthy empty answer, and its only caller threw that
// error away: nothing named the cause, and the `continue` skipped the accounting, so `active` stayed true
// and fill() kept a full window in flight against a resolver refusing everything.
func TestRejectedAnswersAreLoggedAndCollapseTheWindow(t *testing.T) {
	for _, rc := range []dnsmessage.RCode{dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused, dnsmessage.RCodeNameError} {
		t.Run(rc.String(), func(t *testing.T) {
			var sink syncBuf
			restore := swapLogOutput(&sink)
			defer restore()

			var rejecting atomic.Bool
			addr := rcodeResolver(t, &rejecting, rc)
			codec, err := NewCodec("t.example.com")
			if err != nil {
				t.Fatalf("NewCodec: %v", err)
			}
			tr, err := NewDNSClientTransport([]string{addr}, codec)
			if err != nil {
				t.Fatalf("NewDNSClientTransport: %v", err)
			}
			defer tr.Close()
			c, ok := tr.(*dnsClient)
			if !ok {
				t.Fatalf("transport is %T, not *dnsClient", tr)
			}

			// The healthy answers have to land first, or "collapsed" proves nothing — it was never open.
			deadline := time.Now().Add(10 * time.Second)
			for !c.active.Load() && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if !c.active.Load() {
				t.Fatal("the pipeline window never went active on healthy answers — the rest of this test would be vacuous")
			}

			// Now every query is rejected. collapseEmpties of them must age the window back down.
			rejecting.Store(true)
			for c.active.Load() && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if c.active.Load() {
				t.Errorf("%v on every query and the window is still open at %d in flight: a refusing resolver keeps the full pipeline pointed at it",
					rc, pipelineWindow)
			}

			got := sink.String()
			if !strings.Contains(got, "answer rejected") {
				t.Errorf("nothing logged for a resolver answering %v — the operator sees a silent tunnel and blames the network.\nlog was:\n%s", rc, got)
			}
			if !strings.Contains(got, addr) {
				t.Errorf("the log names no resolver, so with several in rotation there is no way to tell which one is refusing.\nlog was:\n%s", got)
			}
		})
	}
}
