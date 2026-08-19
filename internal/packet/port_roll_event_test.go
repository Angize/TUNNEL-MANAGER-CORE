package packet

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Angize/TUNNEL-MANAGER-CORE/internal/crypto"
)

func rollingPort(t *testing.T, ka time.Duration) (*Raw, string) {
	t.Helper()
	r := &Raw{isClient: true, keepalive: ka, profile: "tcp", sportRandom: true, closeCh: make(chan struct{})}
	r.peer.Store(&net.IPAddr{IP: net.IPv4(10, 30, 0, 2)})
	r.cliPort.Store(40000)
	r.link = &capturingLink{r: r}
	path := filepath.Join(t.TempDir(), "core.status")
	r.SetStatusPath(path)
	return r, path
}

func greenSession(t *testing.T, r *Raw) {
	t.Helper()
	sl, err := crypto.NewSealer(crypto.CipherChaCha, "port-refresh-psk-0123456789abcdef", true)
	if err != nil {
		t.Fatal(err)
	}
	r.session.Store(&sealerBox{s: sl})
	if r.link == nil {

		r.link = &capturingLink{r: r}
	}
}

func rollEvents(t *testing.T, path string) []coreEvent {
	t.Helper()
	var out []coreEvent
	for _, e := range coreStatusEvents(t, path) {
		if e.Code == "port-roll" {
			out = append(out, e)
		}
	}
	return out
}

func TestARollingPortSaysSoOncePerOutage(t *testing.T) {
	r, path := rollingPort(t, 6*time.Second)

	for i := 0; i < 5; i++ {
		if !r.rollSourcePort() {
			t.Fatalf("draw %d did not move the port", i+1)
		}
	}
	if ev := rollEvents(t, path); len(ev) != 1 {
		t.Fatalf("%d port-roll events for 5 draws in one outage, want exactly 1. The ring is 500 lines "+
			"fleet-wide and the ladder redraws every few seconds — a line each buries the burn that follows", len(ev))
	}
}

func TestTheNextOutageSaysSoAgain(t *testing.T) {
	r, path := rollingPort(t, 10*time.Second)
	cur := r.peer.Load().IP

	r.rollSourcePort()
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 1 {
		t.Fatalf("first outage wrote %d events, want 1", n)
	}

	r.markRx(cur)
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 2 {
		t.Fatalf("a second outage wrote %d events in total, want 2 — the latch never re-armed", n)
	}
}

func TestOnlyTheCurrentDestinationEndsTheOutage(t *testing.T) {
	r, path := rollingPort(t, 10*time.Second)
	cur, other := r.peer.Load().IP, net.IPv4(10, 30, 0, 3)

	r.rollSourcePort()
	r.markRx(other)
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 1 {
		t.Fatalf("a reply from the endpoint we are NOT on ended the outage on behalf of the one we are "+
			"on: %d events, want 1", n)
	}

	r.markRx(cur)
	r.rollSourcePort()
	if n := len(rollEvents(t, path)); n != 2 {
		t.Fatalf("the current destination answered and the next outage stayed silent: %d events, want 2", n)
	}
}
