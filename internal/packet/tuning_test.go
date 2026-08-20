package packet

import (
	"reflect"
	"testing"
	"time"
)

func TestApplyTuning(t *testing.T) {
	save := struct {
		sb []int64
		dr int64
		ml time.Duration
	}{suspectBackoff, deadRetest, minLiveness}
	defer func() {
		suspectBackoff, deadRetest, minLiveness = save.sb, save.dr, save.ml
	}()

	ApplyTuning(TuningInput{})
	if deadRetest != save.dr || !reflect.DeepEqual(suspectBackoff, save.sb) {
		t.Fatalf("zero input mutated a default: deadRetest=%d backoff=%v", deadRetest, suspectBackoff)
	}

	ApplyTuning(TuningInput{
		SuspectBackoff: []int64{5, 10, 20}, DeadRetestSecs: 900,
		MinLivenessSecs: 12,
	})
	if !reflect.DeepEqual(suspectBackoff, []int64{5, 10, 20}) {
		t.Errorf("suspectBackoff=%v", suspectBackoff)
	}
	if deadRetest != 900 {
		t.Errorf("health FSM: deadRetest=%d", deadRetest)
	}
	if minLiveness != 12*time.Second {
		t.Errorf("durations: minLiveness=%v", minLiveness)
	}

	ApplyTuning(TuningInput{MinLivenessSecs: 999999})
	if minLiveness != 3600*time.Second {
		t.Errorf("minLiveness not clamped: %v", minLiveness)
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
