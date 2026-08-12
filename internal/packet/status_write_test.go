package packet

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFileAtomic used to swallow BOTH the write and the rename error. A full or read-only filesystem then
// looked exactly like a dead tunnel: the status file freezes at its last good contents, the node keeps
// parsing it happily, and the dashboard goes red pointing at the peer while the cause is local disk.
//
// The failure must be REPORTED and must not panic or leave a stray .tmp behind for the reader to trip over.
func TestStatusWriteFailureIsReportedNotSwallowed(t *testing.T) {
	dir := t.TempDir()

	// A path whose PARENT is a regular file: every write there fails, on every platform.
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(notADir, "status.json")

	// Assert on the EMISSION, not on the pending counter: note() emits and then swaps the counter back to
	// zero, so a test reading `n` afterwards sees 0 and concludes nothing happened. Start from a known
	// state, since other tests in this package share the throttle.
	statusWriteLog.last.Store(0)
	statusWriteLog.n.Store(0)
	writeFileAtomic(target, []byte(`{"ok":true}`), 0o644) // must not panic
	if statusWriteLog.last.Load() == 0 {
		t.Error("a failed status write emitted no line; the operator's only clue that the disk is the " +
			"problem is that line, and without it the dashboard blames the peer")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the target must not exist after a failed write")
	}

	// The happy path still works, and leaves no .tmp beside the result.
	ok := filepath.Join(dir, "status.json")
	writeFileAtomic(ok, []byte(`{"ok":true}`), 0o644)
	b, err := os.ReadFile(ok)
	if err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("the good path must still write atomically: %q %v", b, err)
	}
	if _, err := os.Stat(ok + ".tmp"); !os.IsNotExist(err) {
		t.Error("the .tmp must be renamed away, not left for a reader to find")
	}
}
