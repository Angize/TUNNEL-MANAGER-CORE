//go:build linux

package packet

import (
	"net"
	"sync"
	"testing"
)

// scopeRecorder is an injectable antiLeaker installer that records the IP each rule set was scoped
// to. antiLeaker.install is nil in a hand-built carrier precisely so a test never touches the host
// firewall; this fills it in with a spy.
type scopeRecorder struct {
	mu  sync.Mutex
	ips []string
}

func (s *scopeRecorder) installer() func(net.IP) func() {
	return func(peer net.IP) func() {
		s.mu.Lock()
		s.ips = append(s.ips, peer.String())
		s.mu.Unlock()
		return func() {}
	}
}

func (s *scopeRecorder) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ips) == 0 {
		return ""
	}
	return s.ips[len(s.ips)-1]
}

// The anti-leak rules must stay scoped to the endpoint the tunnel is CURRENTLY using.
//
// The rule set is single-scoped: pointing it at one address takes it off the previous one. learnPeer
// ran on the receive goroutine and re-scoped to whoever sent the frame — while a pooled CLIENT
// deliberately does NOT adopt that sender as its peer, and SetPeerPool just as deliberately keeps
// admitting the endpoint a rotation left so frames still in flight from it are not dropped. So every
// one of those stragglers dragged the rules back onto the OLD destination, i.e. OFF the live one:
// the #211 kernel-answer leak, re-opened on the endpoint actually carrying traffic, on every
// rotation. install-before-remove does not help — it closes the sub-millisecond gap between two rule
// sets, not a scope pointed at the wrong address.
//
// The synchronous `scope` calls on the rotate/pin paths were always right; it is only this async
// hand-off that ran backwards.
func TestAntiLeakScopeIsNotDraggedBackByAStragglerFrame(t *testing.T) {
	const live, old = "203.0.113.20", "203.0.113.10"

	t.Run("raw: a pooled client ignores the endpoint a rotation left", func(t *testing.T) {
		rec := &scopeRecorder{}
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.leak.install = rec.installer()
		r.SetPeerPool(NewPeerPool([]string{old, live}, true, 0, ""))
		r.peer.Store(&net.IPAddr{IP: net.ParseIP(live).To4()}) // where a rotation has put us
		r.leak.scope(net.ParseIP(live).To4())                  // ...and the rules follow, as rotatePeerRaw does
		if got := rec.last(); got != live {
			t.Fatalf("pre-scope landed on %q, want %s — the rest of this case would be vacuous", got, live)
		}

		// A frame still in flight from the endpoint we just left.
		r.learnPeer(&net.IPAddr{IP: net.ParseIP(old).To4()})
		r.leak.apply() // scopeAsync hands off to a goroutine; run the same work synchronously

		if got := rec.last(); got != live {
			t.Errorf("a straggler from %s dragged the anti-leak rules onto it; they are now OFF %s, which is the endpoint carrying the tunnel — the #211 kernel-answer leak, re-opened on every rotation", old, live)
		}
	})

	t.Run("flux: same", func(t *testing.T) {
		rec := &scopeRecorder{}
		f := &Flux{isClient: true}
		f.leak.install = rec.installer()
		f.SetPeerPool(NewPeerPool([]string{old, live}, true, 0, ""))
		f.peer.Store(&net.IPAddr{IP: net.ParseIP(live).To4()})
		f.leak.scope(net.ParseIP(live).To4())
		if got := rec.last(); got != live {
			t.Fatalf("pre-scope landed on %q, want %s", got, live)
		}
		f.learnPeer(&net.IPAddr{IP: net.ParseIP(old).To4()})
		f.leak.apply()
		if got := rec.last(); got != live {
			t.Errorf("a straggler from %s dragged the flux anti-leak rules off %s", old, live)
		}
	})

	// ...and the case the hand-off EXISTS for must keep working: a server has no pool, learns its
	// client from the frame, and must follow that client's source rotation.
	t.Run("raw: a server still follows the client it just learned", func(t *testing.T) {
		rec := &scopeRecorder{}
		r := &Raw{isClient: false}
		r.link = &directLink{r: r}
		r.leak.install = rec.installer()

		r.learnPeer(&net.IPAddr{IP: net.ParseIP(old).To4()})
		r.leak.apply()
		if got := rec.last(); got != old {
			t.Fatalf("a server did not scope to the client it learned: got %q, want %s", got, old)
		}
		// The client rotates its source; the server must follow.
		r.learnPeer(&net.IPAddr{IP: net.ParseIP(live).To4()})
		r.leak.apply()
		if got := rec.last(); got != live {
			t.Errorf("a server did not follow its client's source rotation: got %q, want %s — this hand-off is the only thing that can", got, live)
		}
	})
}
