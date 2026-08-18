package packet

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func settleGoroutines() int {
	prev := runtime.NumGoroutine()
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n >= prev {
			return n
		}
		prev = n
	}
	return prev
}

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
		_, _ = conn.Write([]byte("prime"))
		conn.Close()
	}

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
