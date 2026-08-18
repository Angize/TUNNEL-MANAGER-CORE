package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWSPoolReadECHCmd(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "core-x.status")
	p := newWSPool([]string{"1.1.1.1"}, []wsSNIEntry{{host: "a.example", ech: []byte("OLD")}}, status)

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

	p.mu.Lock()
	got := append([]byte(nil), p.snis[0].ech...)
	p.mu.Unlock()
	if !bytes.Equal(got, newECH) {
		t.Fatalf("pool ech = %q, want %q — live push did not hot-swap the key", got, newECH)
	}

	if _, err := os.Stat(status + ".echcmd"); !os.IsNotExist(err) {
		t.Fatal(".echcmd not removed after read — would re-fire every poll")
	}

	os.WriteFile(status+".echcmd", b, 0o600)
	if again := p.readECHCmd(); len(again) != 0 {
		t.Fatalf("re-pushing the SAME key reported %v changed, want none (transition-gated)", again)
	}
}

func TestReadECHCmdSingle(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "core-x.status")
	b := &TCP{ws: true, wsHost: "a.example", wsECH: []byte("OLD"), st: newCoreStatus(status, "ws · edge:443")}

	newECH := []byte("FRESH-single-edge-ech")
	cmd := map[string]map[string]string{"snis": {"a.example": base64.StdEncoding.EncodeToString(newECH)}}
	data, _ := json.Marshal(cmd)
	if err := os.WriteFile(status+".echcmd", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if !b.readECHCmdSingle() {
		t.Fatal("readECHCmdSingle should report a swap")
	}
	if !bytes.Equal(b.wsECH, newECH) {
		t.Fatalf("wsECH = %q, want %q — single-edge live push did not hot-swap", b.wsECH, newECH)
	}
	if _, err := os.Stat(status + ".echcmd"); !os.IsNotExist(err) {
		t.Fatal(".echcmd not removed after read — would re-fire every reconnect")
	}

	os.WriteFile(status+".echcmd", data, 0o600)
	if b.readECHCmdSingle() {
		t.Fatal("re-pushing the SAME key must be a no-op")
	}

	other, _ := json.Marshal(map[string]map[string]string{"snis": {"other.host": base64.StdEncoding.EncodeToString([]byte("X"))}})
	os.WriteFile(status+".echcmd", other, 0o600)
	if b.readECHCmdSingle() || !bytes.Equal(b.wsECH, newECH) {
		t.Fatal("a push for a foreign host must not swap our key")
	}
}
