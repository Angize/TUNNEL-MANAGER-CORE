//go:build linux

package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// trackRot used to take its baseline INSIDE the goroutine it starts:
//
//	go func() {
//		tick := time.NewTicker(time.Second)
//		last := live()          // <- here
//
// so anything that changed between trackRot returning and that goroutine being scheduled was folded
// into the baseline and never reported -- the watcher compares against it forever. For a server that
// is the FIRST client port it learns, which is the one case
// TestTheFileCatchesTheClientPortTheServerLearned exists for: the file keeps the placeholder while
// the wire answers the real port, until something else happens to move a port.
//
// That reads as a flaky test and is a lost update. Measured on a two-core box under four busy loops:
// 31 failures out of 40 before, 0 out of 40 after, with that test unchanged.
//
// This pins it deterministically rather than by load. GOMAXPROCS(1) with nothing but an atomic store
// between the call and the change is what makes it so: a goroutine created on the only P cannot run
// until its creator yields, so the change below is guaranteed to land BEFORE the watcher's first
// look. On the old code the watcher then adopts 40000 as its baseline and never writes again; on the
// new one its baseline is the 0 that was true when trackRot was called, and the first tick reports.
//
// Asserting the number of live() calls instead does NOT work, and looked like it did: setRot writes
// the file on its way in, and writing evaluates the live value, so the count is already 2 before the
// goroutine has run. The first version of this test passed against the broken code.
func TestAChangeMadeBeforeTheWatcherStartsIsStillReported(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	var dport atomic.Uint32
	live := func() rotStatus { return rotStatus{Sport: 51820, Dport: uint16(dport.Load())} }

	st := newCoreStatus(filepath.Join(t.TempDir(), "core.status"), "tcp")
	closeCh := make(chan struct{})
	defer close(closeCh)

	st.trackRot(live, closeCh)
	dport.Store(40000)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if rotDportOnDisk(t, st.path) == 40000 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the port changed while the watcher's goroutine had not run yet, and the file still "+
		"says %d — the baseline swallowed it", rotDportOnDisk(t, st.path))
}

func rotDportOnDisk(t *testing.T, path string) uint16 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Rot rotStatus `json:"rot"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	return got.Rot.Dport
}
