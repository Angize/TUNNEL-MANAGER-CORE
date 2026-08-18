package packet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
