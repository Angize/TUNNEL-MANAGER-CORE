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
		sb                 []int64
		dr, pt             int64
		im, ims, ssm, ssmn int64
		plt                int32
		ml, pto            time.Duration
	}{suspectBackoff, deadRetest, pinTTL,
		idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs, pingLossThreshold,
		minLiveness, probeTimeout}
	defer func() {
		suspectBackoff, deadRetest, pinTTL = save.sb, save.dr, save.pt
		idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs = save.im, save.ims, save.ssm, save.ssmn
		pingLossThreshold = save.plt
		minLiveness, probeTimeout = save.ml, save.pto
	}()

	// A zero input must be a no-op: every default survives.
	ApplyTuning(TuningInput{})
	if pinTTL != save.pt || deadRetest != save.dr || !reflect.DeepEqual(suspectBackoff, save.sb) {
		t.Fatalf("zero input mutated a default: pinTTL=%d deadRetest=%d backoff=%v", pinTTL, deadRetest, suspectBackoff)
	}

	// Real values apply.
	ApplyTuning(TuningInput{
		SuspectBackoff: []int64{5, 10, 20}, DeadRetestSecs: 900, PinTTLSecs: 45,
		IdleMult: 6, IdleMinSecs: 30,
		SessionStaleMult: 2, SessionStaleMinSecs: 8, PingLossThreshold: 5,
		MinLivenessSecs: 12, ProbeTimeoutSecs: 7,
	})
	if !reflect.DeepEqual(suspectBackoff, []int64{5, 10, 20}) {
		t.Errorf("suspectBackoff=%v", suspectBackoff)
	}
	if deadRetest != 900 || pinTTL != 45 {
		t.Errorf("health FSM: deadRetest=%d pinTTL=%d", deadRetest, pinTTL)
	}
	if idleMult != 6 || idleMinSecs != 30 || sessionStaleMult != 2 || sessionStaleMinSecs != 8 || pingLossThreshold != 5 {
		t.Errorf("dead-detect: im=%d ims=%d ssm=%d ssmn=%d plt=%d", idleMult, idleMinSecs, sessionStaleMult, sessionStaleMinSecs, pingLossThreshold)
	}
	if minLiveness != 12*time.Second || probeTimeout != 7*time.Second {
		t.Errorf("durations: minLiveness=%v probeTimeout=%v", minLiveness, probeTimeout)
	}
	// idleFor / the stale window now track the tuned multipliers.
	if got := idleFor(10 * time.Second); got != 60*time.Second { // 6×10s=60s, above the 30s floor
		t.Errorf("idleFor(10s)=%v want 60s", got)
	}
	if got := idleFor(2 * time.Second); got != 30*time.Second { // 6×2s=12s -> floored to 30s
		t.Errorf("idleFor(2s)=%v want 30s (floor)", got)
	}

	// Out-of-range values clamp instead of taking effect verbatim.
	ApplyTuning(TuningInput{PinTTLSecs: 999999, ProbeTimeoutSecs: 999999})
	if pinTTL != 3600 {
		t.Errorf("pinTTL not clamped: %d", pinTTL)
	}
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
