package packet

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func beatHarness(t *testing.T) (beat func(), rolls *int, dead *bool, verdict string) {
	t.Helper()
	dir := t.TempDir()
	rc := newRotationController(nil, nil)
	verdict = filepath.Join(dir, "core.json.verdict")
	rc.setVerdict(verdict)
	rolls, dead = new(int), new(bool)
	rc.port.setRoll(func() bool { *rolls++; return true }, func(time.Time) bool { return *dead })
	beat = func() { rc.pollPins(func() {}, func() {}, func(bool) {}, func(bool) {}, nil, atPathEpoch) }
	return beat, rolls, dead, verdict
}

func landOK(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"cmd":"ok","key":"","epoch":7}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNothingMovesThePortWhileTheTupleAnswers(t *testing.T) {
	beat, rolls, dead, _ := beatHarness(t)
	*dead = false

	for i := 0; i < 8; i++ {
		beat()
	}
	if *rolls != 0 {
		t.Errorf("a tuple that is answering was moved %d time(s). There is no schedule any more: the "+
			"port moves when the judge asks for it or when the tuple has gone silent, and neither has "+
			"happened here", *rolls)
	}
}

func TestTheLocalRepairStandsAsideForALiveJudge(t *testing.T) {
	beat, rolls, dead, verdict := beatHarness(t)
	*dead = true

	beat()
	if *rolls == 0 {
		t.Fatal("with no verdict ever delivered there is no judge to defer to, and the dead tuple " +
			"did not move on the carrier's own evidence")
	}

	was := *rolls
	for i := 1; i <= 3; i++ {
		landOK(t, verdict)
		beat()
		if *rolls != was {
			t.Fatalf("beat %d: a judge is delivering verdicts and the local repair moved the port "+
				"anyway (%d -> %d). Every move spends an epoch, and a verdict whose epoch moved across "+
				"the probe is discarded — the churn eats the verdicts the ladder needs", i, was, *rolls)
		}
	}
}

func TestTheLocalRepairTakesOverWhenTheJudgeGoesQuiet(t *testing.T) {
	var p portRung
	rolls := 0
	p.setRoll(func() bool { rolls++; return true }, func(time.Time) bool { return true })

	base := time.Now()
	p.tick(base, true)
	if rolls != 0 {
		t.Fatalf("the port moved on the beat a verdict landed (%d rolls)", rolls)
	}
	p.tick(base.Add(judgeSilence), false)
	if rolls != 0 {
		t.Fatalf("the ladder gave the port up %v after the last verdict — it owns it for %v", judgeSilence, judgeSilence)
	}
	p.tick(base.Add(judgeSilence+time.Second), false)
	if rolls != 1 {
		t.Fatalf("no verdict for longer than %v means there is no judge left to wait for, and the "+
			"carrier's own repair must take over: got %d rolls", judgeSilence, rolls)
	}
}

func TestATunnelThatWasNeverJudgedRepairsItself(t *testing.T) {
	var p portRung
	rolls := 0
	p.setRoll(func() bool { rolls++; return true }, func(time.Time) bool { return true })

	p.tick(time.Now(), false)
	if rolls != 1 {
		t.Errorf("a tunnel that has never received a verdict has no judge to stand aside for, so its "+
			"own evidence is all it has: got %d rolls", rolls)
	}
}
