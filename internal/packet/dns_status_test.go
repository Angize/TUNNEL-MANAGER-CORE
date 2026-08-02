package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// dns is the one client carrier whose status file the panel needs for both halves of its dot: with no
// `dw` published, instant-red is gated off and a dead tunnel never turns red; with no `hb` there is
// nothing but traffic flow to judge by, so a HEALTHY idle tunnel ages into yellow. Both are visible only
// end to end, so this runs a real client against a real authoritative server and reads the node's file.
func TestDNSClientPublishesStatusAndHeartbeat(t *testing.T) {
	const (
		psk  = "e2e-shared-pre-shared-key-1234567890"
		zone = "t.example.com"
	)
	addr := freeUDPPort(t)

	srvDev, _ := tunPair(t, "dnshbs")
	cliDev, _ := tunPair(t, "dnshbc")

	srv, err := ListenDNS(srvDev, addr, zone, psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenDNS: %v", err)
	}
	cli, err := DialDNS(cliDev, []string{addr}, zone, psk, "aes-256-gcm", time.Second)
	if err != nil {
		t.Fatalf("DialDNS: %v", err)
	}
	statusPath := filepath.Join(t.TempDir(), "core.status")
	cli.SetStatusPath(statusPath)

	go srv.Run()
	go cli.Run()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	read := func() (hb, dw int64) {
		b, err := os.ReadFile(statusPath)
		if err != nil {
			return 0, 0
		}
		var doc struct {
			HB int64 `json:"hb"`
			DW int64 `json:"dw"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return 0, 0
		}
		return doc.HB, doc.DW
	}

	// dw first: it is published at Run and gates the panel's instant-red, so it must not wait for a
	// session to come up — a tunnel that never connects is exactly the one that has to read as dead.
	deadline := time.Now().Add(5 * time.Second)
	var hb, dw int64
	for time.Now().Before(deadline) {
		if _, dw = read(); dw > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dw <= 0 {
		t.Fatalf("no dead window published at %s — the panel cannot age hb, so a dead dns tunnel never goes red", statusPath)
	}
	if want := int64(DNSDeadFloorSecs()); dw < want {
		t.Errorf("published dw=%d is under the carrier's own floor %d — a reader would call the tunnel dead while the session is still healthy", dw, want)
	}

	// Then hb. Nothing is written into either TUN, so this is the IDLE case on purpose: the heartbeat
	// has to come from the session's keepalive round-trip, not from packets this carrier read.
	deadline = time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if hb, _ = read(); hb > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if hb <= 0 {
		t.Fatal("an established but IDLE dns tunnel published no heartbeat — the dot falls back to traffic flow, which is exactly the false-yellow this publishes to prevent")
	}
	if age := time.Now().Unix() - hb; age > dw {
		t.Errorf("published hb is %ds old against a %ds window: a live tunnel reads as dead", age, dw)
	}
}
