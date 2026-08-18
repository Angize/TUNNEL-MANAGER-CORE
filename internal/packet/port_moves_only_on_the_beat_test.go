package packet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func beatHarness(t *testing.T) (beat func(), rolls *int, dead, ready *bool, verdict string) {
	t.Helper()
	dir := t.TempDir()
	rc := newRotationController(nil, nil)
	verdict = filepath.Join(dir, "core.json.verdict")
	rc.setVerdict(verdict)
	rolls, dead, ready = new(int), new(bool), new(bool)
	rc.port.setRoll(func(bool) bool { *rolls++; return true })

	rc.port.setRefresh(func(time.Time) bool { return *dead }, func() bool { return *ready }, time.Nanosecond)
	beat = func() { rc.pollPins(func() {}, func() {}, func(bool) {}, func(bool) {}, nil, atPathEpoch) }
	return beat, rolls, dead, ready, verdict
}

func landOK(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"cmd":"ok","key":"","epoch":7}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTheScheduleStandsAsideForAVerdict(t *testing.T) {
	beat, rolls, _, ready, verdict := beatHarness(t)
	*ready = true

	beat()
	beat()
	if *rolls == 0 {
		t.Fatal("setup: a green tunnel with a due schedule did not roll at all")
	}

	was := *rolls
	landOK(t, verdict)
	beat()
	if *rolls != was {
		t.Errorf("the schedule rolled on the beat a verdict landed: %d -> %d. That is the path moving "+
			"under the judge in the middle of the round it is measuring", was, *rolls)
	}

	beat()
	if *rolls == was {
		t.Error("the schedule never resumed after the verdict — one verdict stopped it for good")
	}
}

func TestTheScheduleWaitsForAGreenTunnel(t *testing.T) {
	beat, rolls, _, ready, _ := beatHarness(t)

	for i := 0; i < 4; i++ {
		beat()
	}
	if *rolls != 0 {
		t.Errorf("a tunnel with no session was refreshed %d time(s) on the schedule", *rolls)
	}

	*ready = true
	beat()
	if *rolls == 0 {
		t.Error("the schedule never fired once the tunnel came up")
	}
}

func TestTheReactiveRollObeysNeitherGate(t *testing.T) {
	beat, rolls, dead, ready, verdict := beatHarness(t)
	*dead, *ready = true, false

	beat()
	if *rolls == 0 {
		t.Fatal("the tuple's return direction was gone and the port did not move")
	}

	was := *rolls
	landOK(t, verdict)
	beat()
	if *rolls == was {
		t.Error("a verdict landing this beat held back the REACTIVE roll — the schedule may wait for " +
			"the judge, this may not")
	}
}
