package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readRT pulls the round-trip fields out of a live status file.
func readRT(t *testing.T, path string) (rt, rttMs, hb int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	var d struct {
		RT  int64 `json:"rt"`
		RTT int64 `json:"rtt_ms"`
		HB  int64 `json:"hb"`
	}
	if json.Unmarshal(b, &d) != nil {
		return 0, 0, 0
	}
	return d.RT, d.RTT, d.HB
}

// TestKeepalivePongIsPublished drives a real UDP tunnel and asserts the client publishes the answered
// keepalive. It is the only fact a single end can observe that covers BOTH directions: the pong proves
// our ping reached the peer AND that its reply reached us. hb proves only the second half, which is why
// a tunnel blackholed upstream keeps hb fresh forever while nothing it sends lands.
func TestKeepalivePongIsPublished(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	const cipher = "aes-256-gcm"
	srvDev, _ := tunPair(t, "rtsrv")
	cliDev, _ := tunPair(t, "rtcli")
	ka := 200 * time.Millisecond
	addr := freeUDPPort(t)

	srv, err := Listen([]string{addr}, srvDev, ka, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	cli, err := Dial(addr, cliDev, ka, false, true, psk, cipher, false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	status := filepath.Join(t.TempDir(), "rt.status")
	cli.SetStatusPath(status)
	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	deadline := time.Now().Add(8 * time.Second)
	var rt, rttMs, hb int64
	for time.Now().Before(deadline) {
		if rt, rttMs, hb = readRT(t, status); rt > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rt == 0 {
		t.Fatalf("no answered keepalive was ever published (hb=%d) — the pong is being discarded, which "+
			"is the whole point of this field", hb)
	}
	if age := time.Now().Unix() - rt; age > 5 {
		t.Fatalf("the published round trip is %ds old on a live tunnel", age)
	}
	if rttMs < 0 || rttMs > 5000 {
		t.Fatalf("rtt_ms = %d, which is not a loopback round trip", rttMs)
	}

	// It must keep advancing: one pong at connect would look identical to a tunnel that later went
	// one-way, which is exactly the state this field exists to expose.
	first := rt
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rt, _, _ = readRT(t, status); rt > first {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the round trip froze at %d — it must advance on every answered keepalive, or a tunnel that "+
		"stops getting through cannot be told from one that never did", first)
}

// TestRoundTripIsSilentWithoutAnAnsweredPing pins the negative half: with no peer at all the client still
// sends pings and still writes a status file, and `rt` must stay 0. A field that fills in on hope would
// be worse than none — it is meant to be the one signal that upstream really works.
func TestRoundTripIsSilentWithoutAnAnsweredPing(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	cliDev, _ := tunPair(t, "rtdead")
	cli, err := Dial(freeUDPPort(t), cliDev, 200*time.Millisecond, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	status := filepath.Join(t.TempDir(), "dead.status")
	cli.SetStatusPath(status)
	go cli.Run()
	t.Cleanup(func() { cli.Close() })

	time.Sleep(2 * time.Second)
	if rt, _, _ := readRT(t, status); rt != 0 {
		t.Fatalf("rt=%d with nothing on the far end — an unanswered keepalive must never look answered", rt)
	}
}
