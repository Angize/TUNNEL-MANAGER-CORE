package packet

import (
	"testing"
	"time"
)

func TestNextReconnectDelay(t *testing.T) {

	loB := time.Duration(float64(reconnectBase) * 0.7)
	hiB := time.Duration(float64(reconnectBase) * 1.3)
	for i := 0; i < 2000; i++ {
		if d := nextReconnectDelay(0); d < loB || d > hiB {
			t.Fatalf("next(0)=%v out of [%v,%v]", d, loB, hiB)
		}
	}

	mid := 4 * time.Second
	lo := time.Duration(float64(mid*2) * 0.7)
	hi := time.Duration(float64(mid*2) * 1.3)
	for i := 0; i < 2000; i++ {
		if d := nextReconnectDelay(mid); d < lo || d > hi {
			t.Fatalf("next(%v)=%v, want ~2x in [%v,%v]", mid, d, lo, hi)
		}
	}

	hardMax := time.Duration(float64(reconnectMax) * 1.3)
	cur := time.Duration(0)
	for i := 0; i < 40; i++ {
		cur = nextReconnectDelay(cur)
		if cur > hardMax {
			t.Fatalf("backoff %v exceeded hard cap %v at step %d", cur, hardMax, i)
		}
	}
	if cur < reconnectMax/2 {
		t.Fatalf("backoff did not climb to the ceiling after 40 steps: %v", cur)
	}
}
