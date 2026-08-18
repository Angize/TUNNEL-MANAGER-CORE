package packet

import (
	"reflect"
	"testing"
	"time"
)

func TestApplyTuning(t *testing.T) {
	save := struct {
		sb      []int64
		dr, dm  int64
		plt     int32
		ml, pto time.Duration
	}{suspectBackoff, deadRetest, deadMult, pingLossThreshold, minLiveness, probeTimeout}
	defer func() {
		suspectBackoff, deadRetest, deadMult = save.sb, save.dr, save.dm
		pingLossThreshold = save.plt
		minLiveness, probeTimeout = save.ml, save.pto
	}()

	ApplyTuning(TuningInput{})
	if deadRetest != save.dr || !reflect.DeepEqual(suspectBackoff, save.sb) {
		t.Fatalf("zero input mutated a default: deadRetest=%d backoff=%v", deadRetest, suspectBackoff)
	}

	ApplyTuning(TuningInput{
		SuspectBackoff: []int64{5, 10, 20}, DeadRetestSecs: 900,
		DeadMult: 6, PingLossThreshold: 5,
		MinLivenessSecs: 12, ProbeTimeoutSecs: 7,
	})
	if !reflect.DeepEqual(suspectBackoff, []int64{5, 10, 20}) {
		t.Errorf("suspectBackoff=%v", suspectBackoff)
	}
	if deadRetest != 900 {
		t.Errorf("health FSM: deadRetest=%d", deadRetest)
	}
	if deadMult != 6 || pingLossThreshold != 5 {
		t.Errorf("dead-detect: dm=%d plt=%d", deadMult, pingLossThreshold)
	}
	if minLiveness != 12*time.Second || probeTimeout != 7*time.Second {
		t.Errorf("durations: minLiveness=%v probeTimeout=%v", minLiveness, probeTimeout)
	}

	for _, ka := range []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second} {
		want := 6 * ka
		if got := deadWindow(ka); got != want {
			t.Errorf("deadWindow(%v)=%v want %v", ka, got, want)
		}
	}

	ApplyTuning(TuningInput{DeadMult: 1})
	if deadMult != 2 {
		t.Errorf("DeadMult=1 must clamp to 2, got %d", deadMult)
	}

	ApplyTuning(TuningInput{ProbeTimeoutSecs: 999999})
	if probeTimeout != 120*time.Second {
		t.Errorf("probeTimeout not clamped: %v", probeTimeout)
	}
}

func TestDefaultLadderDeepens(t *testing.T) {
	if len(suspectBackoff) == 0 {
		t.Fatal("an empty suspect ladder leaves peer_pool indexing suspectBackoff[0] on nothing")
	}
	for i := 1; i < len(suspectBackoff); i++ {
		if suspectBackoff[i] <= suspectBackoff[i-1] {
			t.Errorf("step %d (%ds) does not deepen on step %d (%ds): a repeatedly failing endpoint would be retried as often or sooner",
				i, suspectBackoff[i], i-1, suspectBackoff[i-1])
		}
	}
	if last := suspectBackoff[len(suspectBackoff)-1]; deadRetest < last {
		t.Errorf("deadRetest=%ds is shorter than the last suspect step (%ds): a DEAD endpoint would be retried sooner than a suspect one", deadRetest, last)
	}

	sb, dr := append([]int64(nil), suspectBackoff...), deadRetest
	defer func() { suspectBackoff, deadRetest = sb, dr }()
	ApplyTuning(TuningInput{SuspectBackoff: sb, DeadRetestSecs: dr})
	if !reflect.DeepEqual(suspectBackoff, sb) || deadRetest != dr {
		t.Errorf("a default does not survive its own clamp: backoff %v -> %v, deadRetest %d -> %d", sb, suspectBackoff, dr, deadRetest)
	}
}
