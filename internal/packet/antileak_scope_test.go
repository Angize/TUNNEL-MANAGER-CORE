//go:build linux

package packet

import (
	"net"
	"sync"
	"testing"
)

type scopeRecorder struct {
	mu  sync.Mutex
	ips []string
}

func (s *scopeRecorder) installer() func(net.IP) (func(), bool) {
	return func(peer net.IP) (func(), bool) {
		s.mu.Lock()
		s.ips = append(s.ips, peer.String())
		s.mu.Unlock()
		return func() {}, true
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

func TestAntiLeakScopeIsNotDraggedBackByAStragglerFrame(t *testing.T) {
	const live, old = "203.0.113.20", "203.0.113.10"

	t.Run("raw: a pooled client ignores the endpoint a rotation left", func(t *testing.T) {
		rec := &scopeRecorder{}
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.leak.install = rec.installer()
		r.SetPeerPool(NewPeerPool([]string{old, live}, 0))
		r.peer.Store(&net.IPAddr{IP: net.ParseIP(live).To4()})
		r.leak.scope(net.ParseIP(live).To4())
		if got := rec.last(); got != live {
			t.Fatalf("pre-scope landed on %q, want %s — the rest of this case would be vacuous", got, live)
		}

		r.learnPeer(&net.IPAddr{IP: net.ParseIP(old).To4()})
		r.leak.apply()

		if got := rec.last(); got != live {
			t.Errorf("a straggler from %s dragged the anti-leak rules onto it; they are now OFF %s, which is the endpoint carrying the tunnel — the kernel-answer leak, re-opened on every rotation", old, live)
		}
	})

	t.Run("flux: same", func(t *testing.T) {
		rec := &scopeRecorder{}
		f := &Flux{isClient: true}
		f.leak.install = rec.installer()
		f.SetPeerPool(NewPeerPool([]string{old, live}, 0))
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

		r.learnPeer(&net.IPAddr{IP: net.ParseIP(live).To4()})
		r.leak.apply()
		if got := rec.last(); got != live {
			t.Errorf("a server did not follow its client's source rotation: got %q, want %s — this hand-off is the only thing that can", got, live)
		}
	})
}
