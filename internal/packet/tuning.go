package packet

var (
	suspectBackoff = []int64{600, 1800, 3600}

	deadRetest int64 = 21600

	ladderRevive = []int64{45, 180, 600}
)

type TuningInput struct {
	SuspectBackoff []int64 `json:"suspect_backoff"`
	DeadRetestSecs int64   `json:"dead_retest_secs"`
	LadderRevive   []int64 `json:"ladder_revive"`
}

func ApplyTuning(t TuningInput) {
	if len(t.SuspectBackoff) > 0 {
		suspectBackoff = t.SuspectBackoff
	}
	if len(t.LadderRevive) > 0 {
		ladderRevive = t.LadderRevive
	}
	if t.DeadRetestSecs > 0 {
		deadRetest = t.DeadRetestSecs
	}
}

const (
	ReviveStepMin int64 = 10
	ReviveStepMax int64 = 3600

	BackoffStepMin int64 = 1
	BackoffStepMax int64 = 86400

	DeadRetestMin int64 = 5
	DeadRetestMax int64 = 86400
)
