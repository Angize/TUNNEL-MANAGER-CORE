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
