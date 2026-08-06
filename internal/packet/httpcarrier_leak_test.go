package packet

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

// settleGoroutines waits for the runtime to reach a steady goroutine count: it GCs and polls until
// the number stops falling (async teardown — an h2 conn's reader/writer exit only after the conn is
// closed) or a short budget elapses, then returns the last reading.
func settleGoroutines() int {
	prev := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= prev { // stopped falling — settled
			return n
		}
		prev = n
	}
	return prev
}

// TestHTTPCGrpcNoConnLeakOnRotation guards the grpc teardown path: retiring many sessions must not grow
// the goroutine count, since a retired session's h2 conn was closed only via CloseIdleConnections, which
// can race the async stream teardown. ⚠ NO TEETH: a loopback h2 server tears down promptly, so this does
// NOT reproduce the CDN-latency-dependent leak — it is a no-regression guard, not proof of the fix.
func TestHTTPCGrpcNoConnLeakOnRotation(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	srvDev, _ := tunPair(t, "xhgleak")
	srv, err := ListenHTTPC("127.0.0.1:0", srvDev, time.Second, false, true, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenHTTPC: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.httpcHandler)
	ts := httptest.NewUnstartedServer(mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	go srv.Run()
	t.Cleanup(func() { ts.Close(); srv.Close() })

	b := &TCP{addr: ts.Listener.Addr().String(), ws: true, httpc: true, httpcMode: "grpc",
		wsPath: "/", wsTLS: true, httpcTLS: &tls.Config{InsecureSkipVerify: true}}

	establishAndRetire := func() {
		conn, _, _, err := b.establishHTTPC()
		if err != nil {
			t.Fatalf("establishHTTPC: %v", err)
		}
		_, _ = conn.Write([]byte("prime")) // make the h2 conn fully live before we retire it
		conn.Close()                        // the rotation teardown path: closeFn -> closeIdle -> forceClose
	}

	// Warm up so the http2 package's steady-state goroutines are already spun up before we baseline.
	for i := 0; i < 5; i++ {
		establishAndRetire()
	}
	base := settleGoroutines()

	const rotations = 60
	for i := 0; i < rotations; i++ {
		establishAndRetire()
	}
	after := settleGoroutines()

	if after > base+15 {
		t.Fatalf("goroutine leak across %d grpc rotations: base=%d after=%d (want <= base+15) — retired h2 conns not reaped",
			rotations, base, after)
	}
	t.Logf("grpc rotation leak check: base=%d after=%d across %d rotations", base, after, rotations)
}
