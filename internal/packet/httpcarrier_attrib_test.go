package packet

import (
	"sync/atomic"
	"testing"
)

// TestWarmStandbyBuildSkipsAttribution guards against a rotation freeze: on a failed establish the
// warm-standby build goroutine must NOT run the full differential-probe attribution, which fires several
// establishes and blocks that single goroutine with standbyBuilding still set — so requestStandby()
// no-ops, no standby ever becomes ready, and rotation stops while the open active keeps the tunnel up.
func TestWarmStandbyBuildSkipsAttribution(t *testing.T) {
	// Two dead edges (refused) + one SNI, autoBurn on so attributeFailure is not short-circuited.
	pool := newWSPool([]string{"127.0.0.1:9", "127.0.0.1:10"},
		[]wsSNIEntry{{host: "a.example", path: "/"}}, true, "")
	var probes int32
	b := &TCP{ws: true, httpc: true, httpcMode: "grpc", wsPath: "/", wsTLS: false, pool: pool}
	b.probeFn = func(ip string, sni wsSNIEntry) bool { atomic.AddInt32(&probes, 1); return false }

	// Primary/active dial: a failed establish MUST run the differential probe (edge health depends on it).
	if _, _, _, err := b.establishHTTPC(true); err == nil {
		t.Fatal("establish to a dead edge should fail")
	}
	if atomic.LoadInt32(&probes) == 0 {
		t.Fatal("attribute=true (primary dial): the differential probe should have run on failure")
	}

	// Warm-standby build: a failed establish MUST NOT run the probe — running it here is exactly what
	// blocked the standby builder and froze rotation.
	atomic.StoreInt32(&probes, 0)
	if _, _, _, err := b.establishHTTPC(false); err == nil {
		t.Fatal("establish to a dead edge should fail")
	}
	if got := atomic.LoadInt32(&probes); got != 0 {
		t.Fatalf("attribute=false (warm-standby build): the differential probe must NOT run, but it ran %d times", got)
	}
}
