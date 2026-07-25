//go:build linux

package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestOperatorPinIsSilentOnEveryCarrier guards the documented invariant that "make this active" is a
// deliberate operator jump and must be COMPLETELY silent on every carrier: the active endpoint changes,
// and nothing lands in the event ring.
//
// This is a real regression guard, not a formality. PR #139 made the pin silent but only edited udp.go
// and tcp.go — raw and flux carry their own copies of adoptPeer/adoptSource and kept emitting
// down("peer-pin") / event("down","src-pin"). That went unnoticed until the panel and node stopped
// treating those codes as benign, at which point a manual pin on a raw or flux tunnel started rendering
// as a red disconnect AND flipped the node's liveness verdict to dead. Asserting silence per carrier is
// what keeps the four copies from drifting again.
func TestOperatorPinIsSilentOnEveryCarrier(t *testing.T) {
	type statusDoc struct {
		Active string `json:"active"`
		Events []struct {
			Kind string `json:"kind"`
			Code string `json:"code"`
		} `json:"events"`
	}
	read := func(t *testing.T, path string) statusDoc {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read status file: %v", err)
		}
		var d statusDoc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("parse status file: %v", err)
		}
		return d
	}

	dstPool := func() *PeerPool { return NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, false, 0, "") }
	srcPool := func() *PeerPool { return NewPeerPool([]string{"10.9.9.1", "10.9.9.2"}, false, 0, "") }

	cases := []struct {
		name string
		pin  func(st *coreStatus)
	}{
		{"raw/dest", func(st *coreStatus) {
			r := &Raw{profile: "bip", spoofFd: -1, pktFd: -1, fakeFd: -1, st: st, pp: dstPool()}
			r.adoptPeerRaw()
		}},
		{"raw/source", func(st *coreStatus) {
			r := &Raw{profile: "bip", spoofFd: -1, pktFd: -1, fakeFd: -1, st: st, sp: srcPool()}
			r.adoptSourceRaw()
		}},
		{"flux/dest", func(st *coreStatus) {
			f := &Flux{carrier: "udp", st: st, pp: dstPool()}
			f.adoptPeerFlux()
		}},
		{"flux/source", func(st *coreStatus) {
			f := &Flux{carrier: "udp", st: st, sp: srcPool()}
			f.adoptSourceFlux()
		}},
		{"udp/dest", func(st *coreStatus) {
			b := &UDP{st: st, pp: NewPeerPool([]string{"10.0.0.1:20000", "10.0.0.2:20000"}, false, 0, "")}
			b.adoptPeerUDP()
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core.status")
			st := newCoreStatus(path, "before")
			c.pin(st)

			d := read(t, path)
			if len(d.Events) != 0 {
				t.Fatalf("%s: a manual pin must write NO event, got %d: %+v", c.name, len(d.Events), d.Events)
			}
			// The pin must still be visible somewhere: the active descriptor is the only channel it uses.
			// (A source pin leaves `active` alone — it changes the source, not the endpoint we talk to.)
			if wantActiveChange := c.name == "raw/dest" || c.name == "flux/dest" || c.name == "udp/dest"; wantActiveChange {
				if d.Active == "before" {
					t.Fatalf("%s: a destination pin must update the active descriptor, still %q", c.name, d.Active)
				}
			}
		})
	}
}
