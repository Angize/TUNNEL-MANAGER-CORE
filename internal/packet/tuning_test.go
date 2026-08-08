package packet

import (
	"reflect"
	"testing"
	"time"
)

// TestApplyTuning checks that non-zero config values override the defaults (clamped to range) while
// zero/empty values leave the compiled-in default untouched. Globals are saved and restored so the
// rest of the package's tests keep seeing the real defaults.
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

	// A zero input must be a no-op: every default survives.
	ApplyTuning(TuningInput{})
	if deadRetest != save.dr || !reflect.DeepEqual(suspectBackoff, save.sb) {
		t.Fatalf("zero input mutated a default: deadRetest=%d backoff=%v", deadRetest, suspectBackoff)
	}

	// Real values apply.
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
	// ONE multiplier, and both windows follow keepalive with no floor of their own to pin them.
	for _, ka := range []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second} {
		want := 6 * ka
		if got := idleFor(ka); got != want {
			t.Errorf("idleFor(%v)=%v want %v", ka, got, want)
		}
		if got := sessionStaleWindow(ka, 0); got != want {
			t.Errorf("sessionStaleWindow(%v)=%v want %v -- the datagram window must use the SAME multiplier", ka, got, want)
		}
	}

	// The multiplier floors at 2: keepaliveInterval stretches to 1.3×keepalive, so a 1× window would
	// expire between two pings and kill a healthy idle carrier.
	ApplyTuning(TuningInput{DeadMult: 1})
	if deadMult != 2 {
		t.Errorf("DeadMult=1 must clamp to 2, got %d", deadMult)
	}

	// Out-of-range values clamp instead of taking effect verbatim.
	ApplyTuning(TuningInput{ProbeTimeoutSecs: 999999})
	if probeTimeout != 120*time.Second {
		t.Errorf("probeTimeout not clamped: %v", probeTimeout)
	}
}

// TestDefaultLadderDeepens guards the SHAPE of the compiled-in retest schedule rather than its numbers:
// each step must wait longer than the one before it, a DEAD entry must come back slower than a suspect
// one, and every default must survive its own ApplyTuning clamp untouched.
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

	// Feeding the compiled-in defaults back through ApplyTuning must change nothing. A default outside
	// its own clamp would mean the panel showing that value and saving it unchanged alters behaviour.
	sb, dr := append([]int64(nil), suspectBackoff...), deadRetest
	defer func() { suspectBackoff, deadRetest = sb, dr }()
	ApplyTuning(TuningInput{SuspectBackoff: sb, DeadRetestSecs: dr})
	if !reflect.DeepEqual(suspectBackoff, sb) || deadRetest != dr {
		t.Errorf("a default does not survive its own clamp: backoff %v -> %v, deadRetest %d -> %d", sb, suspectBackoff, dr, deadRetest)
	}
}
