//go:build linux

package packet

import (
	"strings"
	"testing"
)

func poolLines(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, e := range coreStatusEvents(t, path) {
		if e.Kind == "pool" {
			out = append(out, e.Code+" "+e.Detail)
		}
	}
	return out
}

// PeerPool reports "rotation has stopped, one left" for whichever axis it is -- the detail carries the
// axis the pool was attached under. The edge carrier hangs its two axes on two PeerPools, "ip" for the
// edge IPs and "sni" for the fronting names, so both halves raise the line. The single-pool carrier
// counted only its IP half and hard-coded the "ip:" prefix, so an operator whose fronting names were
// all burned got no warning at all: the pool is pinned to its last name and the panel is silent. The
// panel already renders the sni: axis; the core never sent it.
func TestBothEdgeAxesReportAStoppedRotation(t *testing.T) {
	t.Run("the sni axis", func(t *testing.T) {
		b, _, sp := edgeCarrier(t, []string{"e1", "e2"}, []wsSNIEntry{{host: "a"}, {host: "b"}, {host: "c"}})
		sp.markSuspect("a", "tun-probe")
		sp.markSuspect("b", "tun-probe")

		got := poolLines(t, b.st.path)
		if len(got) != 1 || !strings.HasPrefix(got[0], "degraded sni:1/3") {
			t.Fatalf("pool events = %v, want one \"degraded sni:1/3\". Two of three fronting names are "+
				"burned and the rotation is down to its last one; the direct pools raise this on their "+
				"own axes and the panel already has a line for it", got)
		}

		sp.retestNow("a")
		if got := poolLines(t, b.st.path); len(got) != 2 || !strings.HasPrefix(got[1], "restored sni:2/3") {
			t.Fatalf("pool events = %v, want the recovery too", got)
		}
	})

	t.Run("the ip axis is unchanged", func(t *testing.T) {
		b, pp, _ := edgeCarrier(t, []string{"e1", "e2", "e3"}, []wsSNIEntry{{host: "a"}})
		pp.markSuspect("e1", "tun-probe")
		pp.markSuspect("e2", "tun-probe")
		got := poolLines(t, b.st.path)
		if len(got) != 1 || !strings.HasPrefix(got[0], "degraded ip:1/3") {
			t.Fatalf("pool events = %v, want one \"degraded ip:1/3\"", got)
		}
	})

	t.Run("the two axes keep separate books", func(t *testing.T) {
		b, pp, sp := edgeCarrier(t, []string{"e1", "e2"}, []wsSNIEntry{{host: "a"}, {host: "b"}})
		pp.markSuspect("e1", "tun-probe")
		sp.markSuspect("a", "tun-probe")
		got := poolLines(t, b.st.path)
		if len(got) != 2 || !strings.HasPrefix(got[0], "degraded ip:1/2") ||
			!strings.HasPrefix(got[1], "degraded sni:1/2") {
			t.Fatalf("pool events = %v, want one degraded line per axis. Each pool keeps its own watch; "+
				"one watch shared by both axes would swallow the second, and the operator would be told "+
				"only half of what stopped", got)
		}
	})
}
