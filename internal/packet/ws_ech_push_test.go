package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWSPoolReadECHCmd proves the live ECH push path: a node-written .echcmd file is consumed once
// and hot-swaps the fresh key into the pool via updateECH, so the next dial presents it — no rebuild.
func TestWSPoolReadECHCmd(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "core-x.status")
	p := newWSPool([]string{"1.1.1.1"}, []wsSNIEntry{{host: "a.example", ech: []byte("OLD")}}, true, status)

	newECH := []byte("FRESH-ech-config-list-bytes")
	cmd := map[string]map[string]string{"snis": {"a.example": base64.StdEncoding.EncodeToString(newECH)}}
	b, _ := json.Marshal(cmd)
	if err := os.WriteFile(status+".echcmd", b, 0o600); err != nil {
		t.Fatal(err)
	}

	changed := p.readECHCmd()
	if len(changed) != 1 || changed[0] != "a.example" {
		t.Fatalf("readECHCmd changed = %v, want [a.example]", changed)
	}
	// The pool now carries the fresh key (hot-swapped, no rebuild).
	p.mu.Lock()
	got := append([]byte(nil), p.snis[0].ech...)
	p.mu.Unlock()
	if !bytes.Equal(got, newECH) {
		t.Fatalf("pool ech = %q, want %q — live push did not hot-swap the key", got, newECH)
	}
	// The command file is consumed exactly once.
	if _, err := os.Stat(status + ".echcmd"); !os.IsNotExist(err) {
		t.Fatal(".echcmd not removed after read — would re-fire every poll")
	}
	// A second read with the same (now-current) key is a no-op (updateECH transition-gates).
	os.WriteFile(status+".echcmd", b, 0o600)
	if again := p.readECHCmd(); len(again) != 0 {
		t.Fatalf("re-pushing the SAME key reported %v changed, want none (transition-gated)", again)
	}
}
