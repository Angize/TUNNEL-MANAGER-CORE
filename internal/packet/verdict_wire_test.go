package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func judgedPool(t *testing.T, addrs ...string) (*PeerPool, *rotationController) {
	t.Helper()
	dir := t.TempDir()
	p := NewPeerPool(addrs, 0, filepath.Join(dir, "pool.json"))
	rc := newRotationController(p, nil)
	rc.setVerdict(filepath.Join(dir, "core.json.verdict"))
	return p, rc
}

func nodeCmd(t *testing.T, rc *rotationController, c poolCmd) (rotated []string) {
	t.Helper()
	c.Epoch = testPathEpoch
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rc.verdict, data, 0o644); err != nil {
		t.Fatalf("write cmd: %v", err)
	}
	rotDst := func(bool) {
		rc.dst.fail()
		rotated = append(rotated, "dst")
	}
	rotSrc := func(bool) {
		if rc.src != nil {
			rc.src.fail()
		}
		rotated = append(rotated, "src")
	}
	rc.pollPins(func() {}, func() {}, rotDst, rotSrc, nil, atPathEpoch)
	return rotated
}

const testPathEpoch = 7

func atPathEpoch() int64 { return testPathEpoch }

func burnedIn(p *PeerPool) map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]bool{}
	for a, r := range p.health.recs {
		if r != nil {
			out[a] = true
		}
	}
	return out
}

func TestAFreshFailStillBurnsAndAdvances(t *testing.T) {
	p, rc := judgedPool(t, "a", "b")

	measured := p.current()
	rotated := nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: measured})

	if !burnedIn(p)[measured] {
		t.Fatalf("%s was named and active, and was not burned", measured)
	}
	if p.current() == measured {
		t.Fatalf("the pool stayed on the endpoint it just burned (%s)", measured)
	}
	if len(rotated) != 1 || rotated[0] != "dst" {
		t.Fatalf("expected exactly one destination rotation, got %v", rotated)
	}
}

func TestAKeyedOKStillClearsOnlyWhatItNames(t *testing.T) {
	p, rc := judgedPool(t, "a", "b")

	nodeCmd(t, rc, poolCmd{Cmd: cmdFail, Key: "a"})
	if !burnedIn(p)["a"] {
		t.Fatal("setup: a was not burned")
	}
	nodeCmd(t, rc, poolCmd{Cmd: cmdOK, Key: "b"})
	if !burnedIn(p)["a"] {
		t.Fatal("an OK naming b cleared a")
	}
	nodeCmd(t, rc, poolCmd{Cmd: cmdOK, Key: "a"})
	if burnedIn(p)["a"] {
		t.Fatal("an OK naming a did not clear a")
	}
}
