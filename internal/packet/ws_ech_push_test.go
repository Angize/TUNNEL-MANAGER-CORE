package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func pushECH(t *testing.T, b *TCP, host string, ech []byte) {
	t.Helper()
	cmd := map[string]map[string]string{"snis": {host: base64.StdEncoding.EncodeToString(ech)}}
	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.st.echCmdPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnECHPushReachesAPool(t *testing.T) {
	b, p := edgeCarrier(t, []string{"1.1.1.1"}, []wsSNIEntry{{host: "a.example", ech: []byte("OLD")}})

	newECH := []byte("FRESH-ech-config-list-bytes")
	pushECH(t, b, "a.example", newECH)

	changed := b.readECHCmd()
	if len(changed) != 1 || changed[0] != "a.example" {
		t.Fatalf("readECHCmd changed = %v, want [a.example]", changed)
	}

	p.mu.Lock()
	got := append([]byte(nil), p.snis[0].ech...)
	p.mu.Unlock()
	if !bytes.Equal(got, newECH) {
		t.Fatalf("pool ech = %q, want %q — live push did not hot-swap the key", got, newECH)
	}

	if _, err := os.Stat(b.st.echCmdPath()); !os.IsNotExist(err) {
		t.Fatal(".echcmd not removed after read — would re-fire every poll")
	}

	pushECH(t, b, "a.example", newECH)
	if again := b.readECHCmd(); len(again) != 0 {
		t.Fatalf("re-pushing the SAME key reported %v changed, want none (transition-gated)", again)
	}
}

func TestAnECHPushReachesASingleEdge(t *testing.T) {
	dir := t.TempDir()
	b := &TCP{ws: true, wsHost: "a.example", wsECH: []byte("OLD")}
	b.SetStatusPath(filepath.Join(dir, "core-x.status"))

	newECH := []byte("FRESH-single-edge-ech")
	pushECH(t, b, "a.example", newECH)
	if len(b.readECHCmd()) != 1 {
		t.Fatal("readECHCmd should report a swap")
	}
	if !bytes.Equal(b.wsECH, newECH) {
		t.Fatalf("wsECH = %q, want %q — single-edge live push did not hot-swap", b.wsECH, newECH)
	}
	if _, err := os.Stat(b.st.echCmdPath()); !os.IsNotExist(err) {
		t.Fatal(".echcmd not removed after read — would re-fire every reconnect")
	}

	pushECH(t, b, "a.example", newECH)
	if len(b.readECHCmd()) != 0 {
		t.Fatal("re-pushing the SAME key must be a no-op")
	}

	pushECH(t, b, "other.host", []byte("X"))
	if len(b.readECHCmd()) != 0 || !bytes.Equal(b.wsECH, newECH) {
		t.Fatal("a push for a foreign host must not swap our key")
	}
}
