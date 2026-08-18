package packet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatusWriteFailureIsReportedNotSwallowed(t *testing.T) {
	dir := t.TempDir()

	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(notADir, "status.json")

	statusWriteLog.last.Store(0)
	statusWriteLog.n.Store(0)
	writeFileAtomic(target, []byte(`{"ok":true}`), 0o644)
	if statusWriteLog.last.Load() == 0 {
		t.Error("a failed status write emitted no line; the operator's only clue that the disk is the " +
			"problem is that line, and without it the dashboard blames the peer")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the target must not exist after a failed write")
	}

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
