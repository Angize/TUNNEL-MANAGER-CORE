package packet

import "time"

var (
	suspectBackoff = []int64{600, 1800, 3600}

	deadRetest int64 = 21600
)

var (
	minLiveness = 20 * time.Second
)

type TuningInput struct {
	SuspectBackoff  []int64
	DeadRetestSecs  int64
	MinLivenessSecs int64
}

func ApplyTuning(t TuningInput) {
	if len(t.SuspectBackoff) > 0 {
		bs := make([]int64, 0, len(t.SuspectBackoff))
		for _, v := range t.SuspectBackoff {
			if v >= 1 && v <= 86400 {
				bs = append(bs, v)
			}
		}
		if len(bs) > 0 {
			suspectBackoff = bs
		}
	}
	if t.DeadRetestSecs > 0 {
		deadRetest = tclamp(t.DeadRetestSecs, 5, 86400)
	}
	if t.MinLivenessSecs > 0 {
		minLiveness = time.Duration(tclamp(t.MinLivenessSecs, 1, 3600)) * time.Second
	}
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
