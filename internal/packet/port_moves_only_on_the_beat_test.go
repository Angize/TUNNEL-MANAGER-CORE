package packet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// beatHarness is the ladder's poller with a counted port rung and both of its gates under the test's
// hand. Everything runs through pollPins — the real per-tick entry point — so a rule that lived only in
// portRung.tick and was never reached from the beat would show up as a test that cannot move the count.
func beatHarness(t *testing.T) (beat func(), rolls *int, dead, ready *bool, verdict string) {
	t.Helper()
	dir := t.TempDir()
	rc := newRotationController(nil, nil)
	verdict = filepath.Join(dir, "core.json.verdict")
	rc.setVerdict(verdict)
	rolls, dead, ready = new(int), new(bool), new(bool)
	rc.port.setRoll(func(bool) bool { *rolls++; return true })
	// A nanosecond schedule: due on every beat after the first, so the test is about the GATES and
	// never about waiting for a clock.
	rc.port.setRefresh(func(time.Time) bool { return *dead }, func() bool { return *ready }, time.Nanosecond)
	beat = func() { rc.pollPins(func() {}, func() {}, func(bool) {}, func(bool) {}, nil, atPathEpoch) }
	return beat, rolls, dead, ready, verdict
}

// landOK drops a verdict the poller will consume on the next beat. cmdOK on purpose: it is a verdict
// for the purposes of "did one land this beat" without itself moving anything.
func landOK(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"cmd":"ok","key":"","epoch":7}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestTheScheduleStandsAsideForAVerdict is the rule the move exists for.
//
// The scheduled re-roll used to run on a goroutine of the carrier's own, which knew nothing about the
// judge: it could move the path in the middle of the round being measured, and the verdict that came
// back was then about a tuple that no longer existed. On the ladder's beat it can see that a verdict
// landed, and it stands aside for it.
func TestTheScheduleStandsAsideForAVerdict(t *testing.T) {
	beat, rolls, _, ready, verdict := beatHarness(t)
	*ready = true

	beat() // the first beat arms the schedule
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

	beat() // and it resumes once the beat is free again
	if *rolls == was {
		t.Error("the schedule never resumed after the verdict — one verdict stopped it for good")
	}
}

// TestTheScheduleWaitsForAGreenTunnel is the other half. A refresh exists so a CARRYING tuple does not
// become a fixed one; on a tunnel that is not carrying it is not a refresh, it is a blind move during
// an outage the ladder is already working through.
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

// TestTheReactiveRollObeysNeitherGate is the asymmetry, and it is deliberate. The two triggers are not
// the same kind of thing: the schedule is a refresh and may wait, but local evidence that THIS tuple
// stopped carrying is rung zero's own trigger — it is most needed exactly when the tunnel is not green
// and the judge is mid-round, which is when both gates would hold it back.
func TestTheReactiveRollObeysNeitherGate(t *testing.T) {
	beat, rolls, dead, ready, verdict := beatHarness(t)
	*dead, *ready = true, false // not carrying, no session

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
