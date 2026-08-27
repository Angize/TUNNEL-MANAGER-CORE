package packet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

	s.reconnected("udp")
	if got := readEvents(t, path); len(got) != 0 {
		t.Fatalf("initial connect should be silent; got %d events: %+v", len(got), got)
	}

	s.down("stale", "udp")
	evs := readEvents(t, path)
	if len(evs) != 1 || evs[0].Kind != "down" || evs[0].Code != "stale" {
		t.Fatalf("after down: want 1 down/stale, got %+v", evs)
	}

	s.reconnected("udp")
	evs = readEvents(t, path)
	if len(evs) != 2 || evs[1].Kind != "up" || evs[1].Code != "reconnect" {
		t.Fatalf("after recovery: want down then up/reconnect, got %+v", evs)
	}
	if evs[0].Seq >= evs[1].Seq {
		t.Fatalf("seq must be monotonic: %d then %d", evs[0].Seq, evs[1].Seq)
	}

	s.reconnected("udp")
	if evs = readEvents(t, path); len(evs) != 2 {
		t.Fatalf("recovery without a pending down must be silent; got %d events", len(evs))
	}

	var off *coreStatus
	off.down("stale", "udp")
	off.reconnected("udp")
	off.event("down", "stale", "udp")
}

// A status whose live source port the test owns, the way a carrier owns its own.
func statusOnPort(t *testing.T, sport *uint16) (*coreStatus, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "core-x.status")
	s := newCoreStatus(path, "raw · 1.2.3.4")
	s.tracker.setLive(func() (pathKey, bool) {
		return pathKey{Src: "10.0.0.1", Sport: *sport, Dst: "10.0.0.2", Dport: 443}, true
	})
	return s, path
}

// A source-port redraw earns a line only when the PROBE says the tunnel is carrying, and the line
// names the port it is carrying on. The carrier's own reconnect cannot say this: the draw sends a
// handshake of its own, and an answered handshake is exactly what a filtered path still gives -- so
// every draw announced itself as a success while the ladder climbed straight past it, twice an outage.
func TestAPortRedrawIsOnlyNewsIfItWorked(t *testing.T) {
	for _, tc := range []struct {
		name    string
		draws   int
		climbed bool // the ladder went past the source port before anything came back
		carried bool
		wantEv  []string
	}{
		{"never came back: silence", 5, false, false, nil},
		{"came back: one line, naming the port", 5, false, true, []string{"port-roll"}},
		{"no redraw, no line", 0, false, true, nil},
		{"came back AFTER the ladder moved on: not the port's doing", 2, true, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sport := uint16(41337)
			s, path := statusOnPort(t, &sport)
			for i := 0; i < tc.draws; i++ {
				s.portRedrawn()
			}
			if tc.climbed {
				s.portClaimLost()
			}
			if tc.carried {
				s.carrying()
			}

			var got []string
			for _, e := range readEvents(t, path) {
				got = append(got, e.Code)
			}
			if len(got) != len(tc.wantEv) {
				t.Fatalf("%d draws (climbed=%v carried=%v) wrote %v, want %v",
					tc.draws, tc.climbed, tc.carried, got, tc.wantEv)
			}
			for i, c := range tc.wantEv {
				if got[i] != c {
					t.Fatalf("event %d is %q, want %q", i, got[i], c)
				}
			}
			if len(tc.wantEv) > 0 {
				want := "sport:41337 tries:" + strconv.Itoa(tc.draws)
				if d := readEvents(t, path)[0].Detail; d != want {
					t.Fatalf("the line reads %q, want %q -- it must name the port that worked AND how "+
						"many draws it cost, or the operator cannot tell a first-try recovery from a "+
						"budget that was nearly spent", d, want)
				}
			}
		})
	}
}

// ...and the next outage gets its own line: the pending draw is consumed, not latched for ever.
func TestEachOutageGetsItsOwnPortLine(t *testing.T) {
	sport := uint16(40001)
	s, path := statusOnPort(t, &sport)

	s.portRedrawn()
	s.carrying()
	s.carrying() // no redraw since: silent
	s.portRedrawn()
	sport = 40002
	s.carrying()

	var ports []string
	for _, e := range readEvents(t, path) {
		if e.Code == "port-roll" {
			ports = append(ports, e.Detail)
		}
	}
	if len(ports) != 2 || ports[0] != "sport:40001 tries:1" || ports[1] != "sport:40002 tries:1" {
		t.Fatalf("port lines = %v, want one per outage naming the port it recovered on and its own "+
			"count -- a count that carried over would describe the previous outage", ports)
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
