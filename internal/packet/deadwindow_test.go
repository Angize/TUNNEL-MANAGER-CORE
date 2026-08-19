package packet

import (
	"testing"
	"time"
)

func TestEveryCarrierSharesOneDeadWindow(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"

	defer func(d time.Duration) { connIdle = d }(connIdle)
	for _, want := range []time.Duration{5 * time.Second, 15 * time.Second, 40 * time.Second} {
		connIdle = want

		streams := []struct {
			name string
			mk   func() (*TCP, error)
		}{
			{"DialTCP", func() (*TCP, error) {
				return DialTCP("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", false, "")
			}},
			{"DialWS", func() (*TCP, error) {
				return DialWS("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", "cdn.example.com", "/w", true, nil)
			}},
			{"DialWSPool", func() (*TCP, error) {
				return DialWSPool(nil, false, false, psk, "aes-256-gcm", nil, 0, false, "")
			}},
			{"DialHTTPC", func() (*TCP, error) {
				return DialHTTPC("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", "cdn.example.com", "/w", true, nil, "")
			}},
			{"ListenHTTPC", func() (*TCP, error) {
				return ListenHTTPC("127.0.0.1:0", nil, false, false, psk, "aes-256-gcm")
			}},
			{"ListenWS", func() (*TCP, error) {
				return ListenWS("127.0.0.1:0", nil, false, false, psk, "aes-256-gcm", "/w")
			}},
			{"ListenTCP", func() (*TCP, error) {
				return ListenTCP([]string{"127.0.0.1:0"}, nil, false, false, psk, "aes-256-gcm", false, "")
			}},
		}
		for _, s := range streams {
			b, err := s.mk()
			if err != nil {
				t.Fatalf("idle=%v: %s: %v", want, s.name, err)
			}
			if b.idle != want {
				t.Errorf("%s read deadline = %v, want %v — every end must reap on the same window",
					s.name, b.idle, want)
			}
			b.Close()
		}

	}
}
