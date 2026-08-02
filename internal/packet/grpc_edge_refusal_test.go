package packet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGrpcEdgeRefusalNamesTheSwitchToFlip covers the failure a grpc-carrier operator is most likely to
// hit, and the one a bare status code says nothing about: at a Cloudflare edge the Content-Type:
// application/grpc header ALONE draws a 403, until gRPC is enabled on the zone. Other edges answer the
// same shape 200, so it is not universal and the carrier is not at fault — the operator has a switch.
func TestGrpcEdgeRefusalNamesTheSwitchToFlip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   []string
	}{
		{"403 is the zone switch", http.StatusForbidden, []string{"403", "gRPC enabled on the zone", "Network -> gRPC"}},
		{"anything else stays generic", http.StatusBadGateway, []string{"got HTTP 502"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// HTTP/2 over TLS, which is what the carrier really dials: on HTTP/1.1 the client blocks
			// waiting to finish sending a request body that never ends (ContentLength = -1 with a pipe),
			// so the response headers never surface and every case times out instead of being tested.
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "no", tc.status)
			}))
			srv.EnableHTTP2 = true
			srv.StartTLS()
			defer srv.Close()

			b := &TCP{}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err := b.dialHTTPCGrpc(srv.Client(), func() {}, ctx, cancel, srv.URL, "0123456789abcdef0123456789abcdef",
				srv.Listener.Addr().String(), func(*http.Request) {}, 5*time.Second)
			if err == nil {
				t.Fatal("a non-200 must fail the dial")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("the error does not mention %q, so the operator still has to guess: %v", w, err)
				}
			}
			if tc.status == http.StatusForbidden && strings.Contains(err.Error(), "want 200") {
				t.Fatalf("the 403 fell through to the generic message: %v", err)
			}
		})
	}
}
