package packet

import (
	"os"
	"path/filepath"
	"testing"
)

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
		{"direct verdict, dead pair", `{"cmd":"fail","low":"10.0.0.1","high":"192.168.1.1"}`,
			poolCmd{Cmd: cmdFail, Low: "10.0.0.1", High: "192.168.1.1"}},
		{"direct verdict, carrying pair", `{"cmd":"ok","low":"10.0.0.1","high":"192.168.1.1"}`,
			poolCmd{Cmd: cmdOK, Low: "10.0.0.1", High: "192.168.1.1"}},
		{"direct pin", `{"kind":"dst","key":"10.0.0.2"}`,
			poolCmd{Kind: "dst", Key: "10.0.0.2"}},
		{"edge verdict, dead combination", `{"cmd":"fail","low":"a.example","high":"1.1.1.1"}`,
			poolCmd{Cmd: cmdFail, Low: "a.example", High: "1.1.1.1"}},
		{"edge verdict, carrying combination", `{"cmd":"ok","low":"a.example","high":"1.1.1.1"}`,
			poolCmd{Cmd: cmdOK, Low: "a.example", High: "1.1.1.1"}},
		{"edge pin, sni axis", `{"kind":"sni","key":"a.example"}`,
			poolCmd{Kind: "sni", Key: "a.example"}},
		{"a retest of one entry", `{"cmd":"retest","kind":"ip","key":"1.1.1.1"}`,
			poolCmd{Cmd: cmdRetest, Kind: "ip", Key: "1.1.1.1"}},
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

func TestPoolCmdFiresExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmd.json")
	if err := os.WriteFile(path, []byte(`{"cmd":"fail","low":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPoolCmd(path); !ok {
		t.Fatal("the first read must see it")
	}
	if _, ok := readPoolCmd(path); ok {
		t.Fatal("the command survived its own read — a one-second poller would re-apply it forever")
	}
}

func TestPoolCmdRejectsNothingBurgers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmd.json")
	for _, js := range []string{`{}`, `{"high":"192.168.1.1"}`, `not json`, `{"kind":"ip"}`} {
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

// The two mailboxes are separate files, and that is the whole point: one writer each. Sharing one path
// meant a verdict landing between a pin's write and the core's poll replaced it, and the operator was
// told nothing.
func TestTheVerdictAndThePinAreDifferentFiles(t *testing.T) {
	b, _ := edgeCarrier(t, []string{"e1", "e2"}, snis("s1"))
	if b.st.verdictPath() == b.st.pinPath() {
		t.Fatalf("both mailboxes are %q — os.Replace makes the second writer eat the first", b.st.pinPath())
	}
	if err := os.WriteFile(b.st.pinPath(), []byte(`{"kind":"ip","key":"e2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.st.verdictPath(), []byte(`{"cmd":"fail","low":"s1","high":"e1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	b.rc.poll(b.rotateLowTCP, b.rotateHighTCP, b.pinApplied, b.st.pathEpoch)
	if got, _, _ := b.pool.current(); got != "e2" {
		t.Fatalf("the pin was lost behind a verdict written in the same tick: current=%s, want e2", got)
	}
}
