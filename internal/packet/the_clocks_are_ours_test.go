package packet

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEveryCarrierTakesItsClocksFromTheSamePlace(t *testing.T) {
	defer func(i, p time.Duration) { connIdle, pingEvery = i, p }(connIdle, pingEvery)
	connIdle, pingEvery = 41*time.Second, 7*time.Second

	const psk = "clocks-are-ours-psk-0123456789abcd"
	for _, tc := range []struct {
		name string
		mk   func() (*TCP, error)
	}{
		{"DialTCP", func() (*TCP, error) {
			return DialTCP("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", false, "")
		}},
		{"DialWS", func() (*TCP, error) {
			return DialWS("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", "cdn.example.com", "/w", true, nil)
		}},
		{"DialHTTPC", func() (*TCP, error) {
			return DialHTTPC("203.0.113.9:443", nil, false, false, psk, "aes-256-gcm", "cdn.example.com", "/h", true, nil, "")
		}},
		{"ListenWS", func() (*TCP, error) {
			return ListenWS("127.0.0.1:0", nil, false, false, psk, "aes-256-gcm", "/w")
		}},
		{"ListenTCP", func() (*TCP, error) {
			return ListenTCP([]string{"127.0.0.1:0"}, nil, false, false, psk, "aes-256-gcm", false, "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.mk()
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			defer b.Close()
			if b.idle != connIdle {
				t.Errorf("read deadline = %v, want connIdle %v. Every end must reap an abandoned "+
					"connection on the same window, or one side holds a socket the other gave up on",
					b.idle, connIdle)
			}
			if b.ping != pingEvery {
				t.Errorf("ping cadence = %v, want pingEvery %v. A zero here is not a fast ping, it is "+
					"a loop with no wait and a recentData window that never opens", b.ping, pingEvery)
			}
		})
	}
}

func TestTheDirectCarriersTakeTheirPingCadenceToo(t *testing.T) {
	defer func(p time.Duration) { pingEvery = p }(pingEvery)
	pingEvery = 9 * time.Second

	dir := t.TempDir()
	u, err := Dial("127.0.0.1:65000", nil, false, true, "clocks-udp-psk-0123456789abcdefgh", "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer u.Close()
	if u.ping != pingEvery {
		t.Errorf("udp ping cadence = %v, want %v", u.ping, pingEvery)
	}

	srv, err := Listen([]string{"127.0.0.1:0"}, nil, false, true, "clocks-udp-psk-0123456789abcdefgh", "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	if srv.ping != pingEvery {
		t.Errorf("udp server ping cadence = %v, want %v", srv.ping, pingEvery)
	}
	_ = filepath.Join(dir, "unused")
}
