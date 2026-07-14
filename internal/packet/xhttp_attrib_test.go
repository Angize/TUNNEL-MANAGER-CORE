package packet

import (
	"sync/atomic"
	"testing"
)

// TestWarmStandbyBuildSkipsAttribution is the regression test for the rotation freeze proven by the
// production goroutine dump: on a failed establish the warm-standby build goroutine ran the full
// differential-probe attribution (attributeFailure -> differentialProbe -> several probeEdgeFull
// establishes, each bounded by xhttpEstablishTimeout). That blocked the single standby-build
// goroutine for minutes with standbyBuilding still set, so requestStandby() no-op'd, the standby
// never became ready, and proactive rotation silently stopped while the open active kept the tunnel
// up. The fix suppresses attribution on the warm-standby path (establishXHTTP(false)); the primary
// dial (establishXHTTP(true)) still attributes. probeFn stands in for the real network probe so we
// can count whether the differential probe ran at all.
func TestWarmStandbyBuildSkipsAttribution(t *testing.T) {
	// Two dead edges (refused) + one SNI, autoBurn on so attributeFailure is not short-circuited.
	pool := newWSPool([]string{"127.0.0.1:9", "127.0.0.1:10"},
		[]wsSNIEntry{{host: "a.example", path: "/"}}, true, "")
	var probes int32
	b := &TCP{ws: true, xhttp: true, xhMode: "grpc", wsPath: "/", wsTLS: false, pool: pool}
	b.probeFn = func(ip string, sni wsSNIEntry) bool { atomic.AddInt32(&probes, 1); return false }

	// Primary/active dial: a failed establish MUST run the differential probe (edge health depends on it).
	if _, _, _, err := b.establishXHTTP(true); err == nil {
		t.Fatal("establish to a dead edge should fail")
	}
	if atomic.LoadInt32(&probes) == 0 {
		t.Fatal("attribute=true (primary dial): the differential probe should have run on failure")
	}

	// Warm-standby build: a failed establish MUST NOT run the probe — running it here is exactly what
	// blocked the standby builder and froze rotation.
	atomic.StoreInt32(&probes, 0)
	if _, _, _, err := b.establishXHTTP(false); err == nil {
		t.Fatal("establish to a dead edge should fail")
	}
	if got := atomic.LoadInt32(&probes); got != 0 {
		t.Fatalf("attribute=false (warm-standby build): the differential probe must NOT run, but it ran %d times", got)
	}
}
