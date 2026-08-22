package packet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTCPSingleEdgeECHSelfHeal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	b := &TCP{st: newCoreStatus(path, "ws · edge:443"), wsECH: []byte{0x01}}

	b.noteECHSelfHeal("h.example", []byte{0x02, 0x03})
	if !bytes.Equal(b.wsECH, []byte{0x02, 0x03}) {
		t.Fatalf("wsECH should be persisted to the fresh key, got %v", b.wsECH)
	}
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "ech" || evs[0].Code != "self_heal" {
		t.Fatalf("want 1 ech/self_heal event, got %+v", evs)
	}
	if evs[0].Detail != "h.example AgM=" {
		t.Fatalf("detail should carry host + base64 key, got %q", evs[0].Detail)
	}

	b.noteECHSelfHeal("h.example", []byte{0x02, 0x03})
	if evs = readEvents(t, path); len(evs) != 1 {
		t.Fatalf("repeat with an unchanged key must be silent; got %d events", len(evs))
	}

	b.noteECHSelfHeal("h.example", []byte{0x09})
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("a rotated key should emit again; got %d events", len(evs))
	}
}

func TestCoreStatusEventPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	s := newCoreStatus(path, "udp · 1.2.3.4:443")

	s.reconnected("udp", 0)
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("initial connect should be silent; got %d events: %+v", len(got), got)
	}

	s.down("stale", "udp")
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "down" || evs[0].Code != "stale" {
		t.Fatalf("after down: want 1 down/stale, got %+v", evs)
	}

	s.reconnected("udp", 0)
	evs = readEvents(t, path)
	if len(evs) != 2 || evs[1].Kind != "up" || evs[1].Code != "reconnect" {
		t.Fatalf("after recovery: want down then up/reconnect, got %+v", evs)
	}
	if evs[0].Seq >= evs[1].Seq {
		t.Fatalf("seq must be monotonic: %d then %d", evs[0].Seq, evs[1].Seq)
	}

	s.reconnected("udp", 0)
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("recovery without a pending down must be silent; got %d events", len(evs))
	}

	var off *coreStatus
	off.down("stale", "udp")
	off.reconnected("udp", 0)
	off.event("down", "stale", "udp")
}

// A source-port redraw earns a line only when it WORKED, and the line names the port that worked.
// The rung draws one per verdict for as long as an outage lasts, so writing at the draw meant a line
// per draw for a tunnel that never came back.
func TestAPortRedrawIsOnlyNewsIfItWorked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		draws  int
		sport  uint16
		wantEv []string
	}{
		{"never came back: silence", 5, 0, nil},
		{"came back: one line, naming the port", 5, 41337, []string{"port-roll"}},
		{"no redraw, no line", 0, 41337, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core-x.status")
			s := newCoreStatus(path, "raw · 1.2.3.4")
			for i := 0; i < tc.draws; i++ {
				s.portRedrawn()
			}
			s.reconnected("raw", tc.sport)

			var got []string
			for _, e := range readEvents(t, path) {
				got = append(got, e.Code)
			}
			if len(got) != len(tc.wantEv) {
				t.Fatalf("%d draws + sport %d wrote %v, want %v", tc.draws, tc.sport, got, tc.wantEv)
			}
			for i, c := range tc.wantEv {
				if got[i] != c {
					t.Fatalf("event %d is %q, want %q", i, got[i], c)
				}
			}
			if len(tc.wantEv) > 0 {
				if d := readEvents(t, path)[0].Detail; d != "sport:41337" {
					t.Fatalf("the line does not name the port that worked: %q", d)
				}
			}
		})
	}
}

// ...and the next outage gets its own line: the pending draw is consumed, not latched for ever.
func TestEachOutageGetsItsOwnPortLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core-x.status")
	s := newCoreStatus(path, "raw · 1.2.3.4")

	s.portRedrawn()
	s.reconnected("raw", 40001)
	s.reconnected("raw", 40001) // no redraw since: silent
	s.portRedrawn()
	s.reconnected("raw", 40002)

	var ports []string
	for _, e := range readEvents(t, path) {
		if e.Code == "port-roll" {
			ports = append(ports, e.Detail)
		}
	}
	if len(ports) != 2 || ports[0] != "sport:40001" || ports[1] != "sport:40002" {
		t.Fatalf("port lines = %v, want one per outage naming the port it recovered on", ports)
	}
}

func readEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	var st struct {
		Events []coreEvent `json:"events"`
	}
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return st.Events
}
