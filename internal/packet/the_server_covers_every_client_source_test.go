//go:build linux

package packet

import (
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

func addedIPs(ev []string) []string {
	var out []string
	for _, e := range ev {
		if strings.HasPrefix(e, "add ") {
			out = append(out, strings.TrimPrefix(e, "add "))
		}
	}
	sort.Strings(out)
	return out
}

// The raw carrier forges a real L4 header, so the kernel sees the same packets the tunnel does and
// answers them: an RST on the tcp profile, an ICMP port-unreachable on udp. The anti-leak rule that
// silences it is written for ONE client IP, and the server only learns which IP that is from the first
// frame that authenticates. Every time the client rotates its source IP the rule is for the address it
// LEFT, and the kernel answers the new one until a frame gets through.
//
// Measured on the netns lab before this change, a raw/tcp tunnel rotating its source every 10 s over
// 50 s: 17 RSTs out of the server in three bursts, one at start and one on each rotation. So the leak
// was not a startup curiosity, it recurred on exactly the schedule the operator set for rotation.
//
// The server is not guessing. peer_src_ips is in its config and it already keeps the list for its
// receive filter. Now it also scopes the anti-leak to every address in it, before Run, so no rotation
// can arrive at an address the firewall has not heard of.
func TestTheServerCoversEveryClientSourceUpFront(t *testing.T) {
	pool := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	for _, tc := range []struct {
		name  string
		build func(rec *leakRecorder) interface{ SetPeerSources([]string) }
	}{
		{"raw", func(rec *leakRecorder) interface{ SetPeerSources([]string) } {
			r := &Raw{profile: "tcp", closeCh: make(chan struct{})}
			r.link = &directLink{r: r}
			r.leak.init(r.closeCh, rec.install)
			return r
		}},
		{"flux", func(rec *leakRecorder) interface{ SetPeerSources([]string) } {
			f := &Flux{carrier: "udp", closeCh: make(chan struct{})}
			f.leak.init(f.closeCh, rec.install)
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &leakRecorder{}
			s := tc.build(rec)
			s.SetPeerSources(pool)

			got := addedIPs(rec.events())
			if len(got) != len(pool) {
				t.Fatalf("the server scoped %v, want a rule for every client source %v — the ones it "+
					"missed are answered by the kernel until a frame from them authenticates", got, pool)
			}
			for i, want := range pool {
				if got[i] != want {
					t.Fatalf("scoped %v, want %v", got, pool)
				}
			}
		})
	}
}

// Hearing from an address the rules already cover must install nothing: a second rule for the same
// address is churn on the firewall, and removing the first one later would open the hole again.
func TestALearnedPeerAddsNothingTheCoverAlreadyHas(t *testing.T) {
	rec := &leakRecorder{}
	r := &Raw{profile: "tcp", closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.leak.init(r.closeCh, rec.install)
	r.SetPeerSources([]string{"10.0.0.1", "10.0.0.2"})
	before := len(rec.events())

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"} {
		r.learnPeer(&net.IPAddr{IP: net.ParseIP(ip)})
	}
	time.Sleep(150 * time.Millisecond)

	if got := rec.events(); len(got) != before {
		t.Fatalf("the receive path touched the firewall for addresses already covered: %v", got)
	}
}

// A source the cover does not name still gets a rule, so a server without a configured pool keeps the
// behaviour it had.
func TestAnUncoveredPeerIsStillScoped(t *testing.T) {
	rec := &leakRecorder{}
	r := &Raw{profile: "tcp", closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.leak.init(r.closeCh, rec.install)
	r.SetPeerSources([]string{"10.0.0.1"})

	r.leak.scope(net.ParseIP("10.0.0.9"))
	if got := addedIPs(rec.events()); len(got) != 2 || got[1] != "10.0.0.9" {
		t.Fatalf("an address outside the cover was not scoped: %v", got)
	}
}

// Every rule the cover installed has to come out when the tunnel closes, or the node's sweep is left
// holding them.
func TestTheCoverIsRemovedOnTeardown(t *testing.T) {
	rec := &leakRecorder{}
	r := &Raw{profile: "tcp", closeCh: make(chan struct{})}
	r.link = &directLink{r: r}
	r.leak.init(r.closeCh, rec.install)
	r.SetPeerSources([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})

	r.leak.teardown()
	var dels []string
	for _, e := range rec.events() {
		if strings.HasPrefix(e, "del ") {
			dels = append(dels, strings.TrimPrefix(e, "del "))
		}
	}
	sort.Strings(dels)
	if len(dels) != 3 {
		t.Fatalf("teardown removed %v, want all three", dels)
	}
}
