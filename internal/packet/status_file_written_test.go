package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The status file is how a core's own account of itself reaches the operator: the event ring carries
// self-heal reasons and startup configuration warnings into the panel's system log, and `active` names
// the endpoint those events happened on. A carrier that never wires the file is silent about all of it,
// and silence is indistinguishable from "nothing went wrong" — so this pins the seam itself, on BOTH
// roles and on a datagram carrier and dns alike.
//
// What it does NOT prove: that any particular event fires. A healthy tunnel raises none, which is why
// this asserts the file and its `active` descriptor rather than waiting for a reason to appear.
func TestEveryStatusPathCarrierWritesItsFile(t *testing.T) {
	const psk = "e2e-shared-pre-shared-key-1234567890"
	dir := t.TempDir()

	read := func(path string) (active string, ts int64, ok bool) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", 0, false
		}
		var doc struct {
			Active string `json:"active"`
			TS     int64  `json:"ts"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return "", 0, false
		}
		return doc.Active, doc.TS, true
	}

	type carrier interface {
		SetStatusPath(string)
		Run() error
		Close() error
	}
	// One case per role and per status-file writer. dns is here because it re-dials into a brand new
	// session on every recovery, which is the shape most likely to lose its writer in a refactor.
	udpAddr, dnsAddr := freeUDPPort(t), freeUDPPort(t)
	srvDev, _ := tunPair(t, "sfwus")
	cliDev, _ := tunPair(t, "sfwuc")
	dnsSrvDev, _ := tunPair(t, "sfwds")
	dnsCliDev, _ := tunPair(t, "sfwdc")

	usrv, err := Listen([]string{udpAddr}, srvDev, time.Second, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ucli, err := Dial(udpAddr, cliDev, time.Second, false, true, psk, "aes-256-gcm", false, 0, 0)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	dsrv, err := ListenDNS(dnsSrvDev, dnsAddr, "t.example.com", psk, "aes-256-gcm")
	if err != nil {
		t.Fatalf("ListenDNS: %v", err)
	}
	dcli, err := DialDNS(dnsCliDev, []string{dnsAddr}, "t.example.com", psk, "aes-256-gcm", time.Second)
	if err != nil {
		t.Fatalf("DialDNS: %v", err)
	}

	cases := []struct {
		name   string
		c      carrier
		want   string // substring the `active` descriptor must name
		status string
	}{
		{"udp server", usrv, "udp", filepath.Join(dir, "usrv.status")},
		{"udp client", ucli, "udp", filepath.Join(dir, "ucli.status")},
		{"dns client", dcli, "dns · t.example.com", filepath.Join(dir, "dcli.status")},
	}
	for _, tc := range cases {
		tc.c.SetStatusPath(tc.status)
	}
	for _, c := range []carrier{usrv, ucli, dsrv, dcli} {
		go c.Run()
		t.Cleanup(func() { c.Close() })
	}

	for _, tc := range cases {
		deadline := time.Now().Add(8 * time.Second)
		var active string
		var ts int64
		var ok bool
		for time.Now().Before(deadline) {
			if active, ts, ok = read(tc.status); ok {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ok {
			t.Errorf("%s: no status file at %s — this end's self-heal reasons and config warnings reach nobody",
				tc.name, tc.status)
			continue
		}
		if active == "" {
			t.Errorf("%s: the status file names no active endpoint, so an event in it says nothing about where it happened", tc.name)
		}
		if len(tc.want) > 0 && !contains(active, tc.want) {
			t.Errorf("%s: active = %q, want it to name %q", tc.name, active, tc.want)
		}
		if ts <= 0 {
			t.Errorf("%s: the status file carries no timestamp, so a reader cannot tell a fresh file from a stale one", tc.name)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
