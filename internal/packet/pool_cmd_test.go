package packet

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOnePoolCmdReadsBothWriters is the compatibility this merge rests on. The node writes these files,
// and it writes a DIFFERENT set of keys for each pool: {cmd,key,src} for a direct pool, {cmd,ip,sni} for
// the edge pool, {key} or {kind,key} for a pin. One struct now reads all of them, and every field is
// optional on the wire — so this drives the exact JSON each writer produces, byte for byte.
func TestOnePoolCmdReadsBothWriters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmd.json")
	read := func(js string) (poolCmd, bool) {
		t.Helper()
		if err := os.WriteFile(path, []byte(js), 0o644); err != nil {
			t.Fatal(err)
		}
		return readPoolCmd(path)
	}

	cases := []struct {
		name string
		js   string
		want poolCmd
	}{
		{"direct verdict, dead destination", `{"cmd":"fail","key":"10.0.0.1"}`,
			poolCmd{Cmd: cmdFail, Key: "10.0.0.1"}},
		{"direct verdict, carrying pair", `{"cmd":"ok","key":"10.0.0.1","src":"192.168.1.1"}`,
			poolCmd{Cmd: cmdOK, Key: "10.0.0.1", Src: "192.168.1.1"}},
		{"direct pin", `{"key":"10.0.0.2"}`,
			poolCmd{Key: "10.0.0.2"}},
		{"edge verdict, dead combination", `{"cmd":"fail","ip":"1.1.1.1","sni":"a.example"}`,
			poolCmd{Cmd: cmdFail, IP: "1.1.1.1", SNI: "a.example"}},
		{"edge verdict, carrying combination", `{"cmd":"ok","ip":"1.1.1.1","sni":"a.example"}`,
			poolCmd{Cmd: cmdOK, IP: "1.1.1.1", SNI: "a.example"}},
		{"edge pin, sni axis", `{"kind":"sni","key":"a.example"}`,
			poolCmd{Kind: "sni", Key: "a.example"}},
	}
	for _, c := range cases {
		got, ok := read(c.js)
		if !ok {
			t.Errorf("%s: %s was rejected", c.name, c.js)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n  got  %+v\n  want %+v", c.name, got, c.want)
		}
	}
}

// TestPoolCmdFiresExactlyOnce: the file is the whole handshake, so it must be removed as it is read.
// Left behind, the same verdict would be re-applied on every tick of a one-second poller — one probe
// result would walk the entire pool.
func TestPoolCmdFiresExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmd.json")
	if err := os.WriteFile(path, []byte(`{"cmd":"fail","key":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPoolCmd(path); !ok {
		t.Fatal("the first read must see it")
	}
	if _, ok := readPoolCmd(path); ok {
		t.Fatal("the command survived its own read — a one-second poller would re-apply it forever")
	}
}

// TestPoolCmdRejectsNothingBurgers: a file that names neither an action nor an entry is not a command.
// Accepting one would hand the switch above it an empty key, and an empty key matches no entry — the
// verdict would land on whatever the fallback picks.
func TestPoolCmdRejectsNothingBurgers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmd.json")
	for _, js := range []string{`{}`, `{"src":"192.168.1.1"}`, `not json`, `{"ip":"1.1.1.1"}`} {
		if err := os.WriteFile(path, []byte(js), 0o644); err != nil {
			t.Fatal(err)
		}
		if c, ok := readPoolCmd(path); ok {
			t.Errorf("%s was accepted as a command: %+v", js, c)
		}
	}
	if _, ok := readPoolCmd(""); ok {
		t.Error("a pool with no status path has no command file, and must not claim one")
	}
}

// TestWSPoolPinDefaultsToTheEdgeAxis: the panel's pin button has always meant "activate this EDGE", and
// an unset axis must keep meaning that. Left empty it would look the key up in the SNI map, find nothing,
// and the operator's pick would silently do nothing.
func TestWSPoolPinDefaultsToTheEdgeAxis(t *testing.T) {
	p := newWSPool([]string{"e1"}, snis("s1"), filepath.Join(t.TempDir(), "status.json"))
	if err := os.WriteFile(p.cmdPath(), []byte(`{"key":"e1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ok := p.readCmd()
	if !ok {
		t.Fatal("the pin was rejected")
	}
	if c.Kind != "ip" {
		t.Fatalf("an axis-less pin resolved to %q, want \"ip\"", c.Kind)
	}
}
