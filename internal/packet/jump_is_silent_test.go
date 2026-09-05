//go:build linux

package packet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAnOperatorJumpIsSilentOnEveryCarrier(t *testing.T) {
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

	dstPool := func() *PeerPool { return NewPeerPool([]string{"10.0.0.1", "10.0.0.2"}, 0) }
	srcPool := func() *PeerPool { return NewPeerPool([]string{"10.9.9.1", "10.9.9.2"}, 0) }

	cases := []struct {
		name string
		jump func(st *coreStatus)
	}{
		{"raw/dest", func(st *coreStatus) {
			r := &Raw{profile: "bare", fakeFd: -1, st: st, pp: dstPool()}
			r.link = &directLink{r: r}
			r.adoptPeerRaw()
		}},
		{"raw/source", func(st *coreStatus) {
			r := &Raw{profile: "bare", fakeFd: -1, st: st, sp: srcPool()}
			r.link = &directLink{r: r}
			r.adoptSourceRaw()
		}},
		{"udp/dest", func(st *coreStatus) {
			b := &UDP{st: st, pp: NewPeerPool([]string{"10.0.0.1:20000", "10.0.0.2:20000"}, 0)}
			b.adoptPeerUDP()
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core.status")
			st := newCoreStatus(path, "before")
			c.jump(st)

			d := read(t, path)
			if len(d.Events) != 0 {
				t.Fatalf("%s: a manual jump must write NO event, got %d: %+v", c.name, len(d.Events), d.Events)
			}

			if wantActiveChange := c.name == "raw/dest" || c.name == "udp/dest"; wantActiveChange {
				if d.Active == "before" {
					t.Fatalf("%s: a destination jump must update the active descriptor, still %q", c.name, d.Active)
				}
			}
		})
	}
}
