//go:build linux

package packet

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stallRig(t *testing.T) (*stallWatch, *coreStatus, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core.status")
	return &stallWatch{}, newCoreStatus(path, "udp · d1:443"), path
}

// The panel suppresses its own coarse "disconnected" line for every core transport, on the promise
// that the core sends a precise code instead. tcp and ws send one on every connection death; udp and
// raw sent nothing but "rehandshake", which the panel reads as a rotation event and paints yellow.
// A dead udp tunnel therefore produced no red line at all -- and then a green "reconnected" for an
// outage the operator was never told about.
func TestAStalledDatagramCarrierSaysSo(t *testing.T) {
	w, st, path := stallRig(t)
	t0 := time.Now()

	w.beat(true, st, "udp", t0)
	if got := codes(coreStatusEvents(t, path)); len(got) != 0 {
		t.Fatalf("a carrier that is answering wrote %v", got)
	}

	w.beat(false, st, "udp", t0.Add(connIdle-time.Second))
	if got := codes(coreStatusEvents(t, path)); len(got) != 0 {
		t.Fatalf("one second short of the idle window wrote %v -- a keepalive gap is not an outage", got)
	}

	w.beat(false, st, "udp", t0.Add(connIdle))
	if got := codes(coreStatusEvents(t, path)); len(got) != 1 || got[0] != "ping_timeout" {
		t.Fatalf("events = %v, want exactly ping_timeout: the code the panel already paints red", got)
	}

	for i := 1; i <= 5; i++ {
		w.beat(false, st, "udp", t0.Add(connIdle*time.Duration(i+1)))
	}
	if got := codes(coreStatusEvents(t, path)); len(got) != 1 {
		t.Fatalf("a five-minute outage wrote %v; one outage is one line, not one per keepalive", got)
	}

	w.beat(true, st, "udp", t0.Add(10*time.Minute))
	got := codes(coreStatusEvents(t, path))
	if len(got) != 2 || got[1] != "reconnect" {
		t.Fatalf("events = %v, want the drop then the recovery -- a red line with no green one leaves "+
			"the tunnel looking down for ever", got)
	}

	w.beat(false, st, "udp", t0.Add(10*time.Minute+connIdle))
	if got := codes(coreStatusEvents(t, path)); len(got) != 3 || got[2] != "ping_timeout" {
		t.Fatalf("events = %v; the second outage must be reported too", got)
	}
}

// A carrier that has never carried is not a carrier that dropped. The node's probe covers "never came
// up"; reporting it here would put a red line on every tunnel for the first minute of its life.
func TestACarrierThatNeverAnsweredIsNotReportedAsDropped(t *testing.T) {
	w, st, path := stallRig(t)
	t0 := time.Now()
	for i := 1; i <= 10; i++ {
		w.beat(false, st, "udp", t0.Add(connIdle*time.Duration(i)))
	}
	if got := codes(coreStatusEvents(t, path)); len(got) != 0 {
		t.Fatalf("events = %v, want silence until the tunnel has carried at least once", got)
	}
}

// The wiring, not the helper: both client loops must actually read the tick and beat the watch, or
// the cases above prove nothing about production.
func TestBothDatagramClientLoopsBeatTheStallWatch(t *testing.T) {
	for _, tc := range []struct{ file, fn, tag string }{
		{"udp.go", "func (b *UDP) clientLoop()", `"udp"`},
		{"raw_linux.go", "func (r *Raw) clientLoop()", `"raw"`},
	} {
		body := funcBody(t, tc.file, tc.fn)
		if !strings.Contains(body, ".rxTick.Swap(false)") || !strings.Contains(body, "stall.beat(") ||
			!strings.Contains(body, tc.tag) {
			t.Errorf("%s does not beat the stall watch with its own tag; a dead %s tunnel would still "+
				"produce no precise down code, and the panel suppresses its own", tc.fn, tc.tag)
		}
	}
}
