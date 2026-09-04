package packet

import "time"

var (
	suspectBackoff = []int64{600, 1800, 3600}

	deadRetest int64 = 21600

	ladderRevive = []int64{45, 180, 600}
)

var (
	minLiveness = 20 * time.Second
)

type TuningInput struct {
	SuspectBackoff  []int64
	DeadRetestSecs  int64
	MinLivenessSecs int64
	LadderRevive    []int64
}

func ApplyTuning(t TuningInput) {
	if bs := tsteps(t.SuspectBackoff, backoffStepMin, backoffStepMax); len(bs) > 0 {
		suspectBackoff = bs
	}
	if rv := tsteps(t.LadderRevive, reviveStepMin, reviveStepMax); len(rv) > 0 {
		ladderRevive = rv
	}
	if t.DeadRetestSecs > 0 {
		deadRetest = tclamp(t.DeadRetestSecs, 5, 86400)
	}
	if t.MinLivenessSecs > 0 {
		minLiveness = time.Duration(tclamp(t.MinLivenessSecs, 1, 3600)) * time.Second
	}
}

const (
	reviveStepMin int64 = 10
	reviveStepMax int64 = 3600

	backoffStepMin int64 = 1
	backoffStepMax int64 = 86400
)

func tsteps(in []int64, lo, hi int64) []int64 {
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if v >= lo && v <= hi {
			out = append(out, v)
		}
	}
	return out
}

func tclamp[T int | int32 | int64](v, lo, hi T) T {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
