package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// resetCfgWarns puts the package-level sink back to its zero state, so one test's notes cannot leak
// into the next. Registered with t.Cleanup by every test that touches it.
func resetCfgWarns(t *testing.T) {
	t.Helper()
	cfgWarns.mu.Lock()
	cfgWarns.pending, cfgWarns.sink = nil, nil
	cfgWarns.mu.Unlock()
	t.Cleanup(func() {
		cfgWarns.mu.Lock()
		cfgWarns.pending, cfgWarns.sink = nil, nil
		cfgWarns.mu.Unlock()
	})
}

func statusEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Events []coreEvent `json:"events"`
	}
	if err := json.Unmarshal(buf, &doc); err != nil {
		t.Fatalf("parse status: %v", err)
	}
	return doc.Events
}

// TestAConfigWarningReachesTheStatusFile pins that a setting the host did not grant reaches the layer
// the operator reads. A journal line does not: the node reads the core's journal only on the failure
// branch after a build, so a core that started with clamped buffers reports nothing. The ORDER is the
// difficulty, and why this is tested — sockets are sized before main wires the sink, so a note must wait.
func TestAConfigWarningReachesTheStatusFile(t *testing.T) {
	t.Run("raised before the status file exists", func(t *testing.T) {
		resetCfgWarns(t)
		noteCfgWarn("sockbuf-clamped", "send 16777216 425984")

		path := filepath.Join(t.TempDir(), "core.status")
		_ = newCoreStatus(path, "udp · 203.0.113.5")

		ev := statusEvents(t, path)
		if len(ev) != 1 {
			t.Fatalf("the status file carries %d event(s), want 1 — a warning raised before the status "+
				"file was wired was dropped, which is every warning the socket setup produces: %+v", len(ev), ev)
		}
		if ev[0].Kind != "cfg" || ev[0].Code != "sockbuf-clamped" {
			t.Fatalf("event = %s/%s, want cfg/sockbuf-clamped", ev[0].Kind, ev[0].Code)
		}
		if ev[0].Detail != "send 16777216 425984" {
			t.Fatalf("detail = %q, want the raw numbers — the core sends DATA and the panel owns the "+
				"Persian, like every other event code", ev[0].Detail)
		}
	})

	t.Run("raised after it exists", func(t *testing.T) {
		resetCfgWarns(t)
		path := filepath.Join(t.TempDir(), "core.status")
		_ = newCoreStatus(path, "udp · 203.0.113.5")
		noteCfgWarn("sockbuf-clamped", "receive 16777216 425984")

		ev := statusEvents(t, path)
		if len(ev) != 1 || ev[0].Code != "sockbuf-clamped" {
			t.Fatalf("a warning raised after the sink existed did not reach the file: %+v", ev)
		}
		if ev[0].Detail != "receive 16777216 425984" {
			t.Fatalf("detail = %q, want the receive-direction numbers", ev[0].Detail)
		}
	})
}
