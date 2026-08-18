//go:build linux

package packet

import (
	"errors"
	"net"
	"sync"
	"testing"
)

type fakeResolver struct {
	mu   sync.Mutex
	seen []string
	err  error
}

func (f *fakeResolver) resolve(ip net.IP) (*l2route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, ip.String())
	if f.err != nil {
		return nil, f.err
	}
	return &l2route{ifindex: 1}, nil
}

func (f *fakeResolver) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func testInjector(f *fakeResolver) *l2inject {
	return &l2inject{fd: -1, resolve: f.resolve}
}

func TestL2InjectResolvesPerDestination(t *testing.T) {
	f := &fakeResolver{}
	inj := testInjector(f)
	a, b := net.IPv4(203, 0, 113, 5), net.IPv4(198, 51, 100, 7)

	_ = inj.sendTo(a, []byte{0x45})
	_ = inj.sendTo(a, []byte{0x45})
	if got := f.asked(); len(got) != 1 || got[0] != a.String() {
		t.Fatalf("resolver calls = %v, want exactly one for %s (the cache must hold)", got, a)
	}

	_ = inj.sendTo(b, []byte{0x45})
	if got := f.asked(); len(got) != 2 || got[1] != b.String() {
		t.Fatalf("resolver calls = %v, want a second call for %s after the destination changed", got, b)
	}

	_ = inj.sendTo(a, []byte{0x45})
	if got := f.asked(); len(got) != 3 || got[2] != a.String() {
		t.Fatalf("resolver calls = %v, want a re-resolve for %s", got, a)
	}

	f2 := &fakeResolver{err: errors.New("no next hop")}
	inj2 := testInjector(f2)
	if err := inj2.sendTo(a, []byte{0x45}); err == nil {
		t.Fatal("sendTo must return the resolver error, not send blind")
	}
	if inj2.rt != nil {
		t.Fatal("a failed resolve cached a route")
	}
}

func TestRawBadsumDecoyFollowsDestination(t *testing.T) {
	f := &fakeResolver{}
	r := &Raw{isClient: true, proto: protoBare, profile: "bare", fakeFd: -1}
	r.link = &directLink{r: r}
	r.localIP.Store(&net.IPAddr{IP: net.IPv4(192, 0, 2, 1)})
	r.desync = newDesyncCfg(true, 4, 2, "badsum")
	r.inj = testInjector(f)

	first := &net.IPAddr{IP: net.IPv4(203, 0, 113, 5)}
	second := &net.IPAddr{IP: net.IPv4(198, 51, 100, 7)}

	r.peer.Store(first)
	r.sendFakes(first)
	if got := f.asked(); len(got) == 0 || got[0] != first.IP.String() {
		t.Fatalf("first handshake resolved %v, want %s", got, first.IP)
	}

	r.peer.Store(second)
	r.sendFakes(second)
	last := f.asked()
	if last[len(last)-1] != second.IP.String() {
		t.Fatalf("after a destination rotation the decoys were still framed for %s; "+
			"the badsum injector must follow the tunnel to %s", last[len(last)-1], second.IP)
	}
}

func TestRawBadsumDecoyFramesForTheRoutedPeer(t *testing.T) {
	peer := &net.IPAddr{IP: net.IPv4(203, 0, 113, 5)}
	decoy := net.IPv4(198, 51, 100, 200)
	forgedSrc := net.IPv4(192, 0, 2, 44)

	for _, tc := range []struct {
		name string
		link func(r *Raw) ipLink
	}{
		{"direct", func(r *Raw) ipLink { return &directLink{r: r} }},
		{"forge src", func(r *Raw) ipLink {
			return &forgedLink{r: r, spoofFd: -1, pktFd: -1, spoofSrc: forgedSrc}
		}},
		{"forge dst", func(r *Raw) ipLink {
			return &forgedLink{r: r, spoofFd: -1, pktFd: -1, spoofDst: decoy}
		}},
		{"forge both", func(r *Raw) ipLink {
			return &forgedLink{r: r, spoofFd: -1, pktFd: -1, spoofSrc: forgedSrc, spoofDst: decoy}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeResolver{}
			r := &Raw{isClient: true, proto: protoBare, profile: "bare", fakeFd: -1}
			r.link = tc.link(r)
			r.localIP.Store(&net.IPAddr{IP: net.IPv4(192, 0, 2, 1)})
			r.desync = newDesyncCfg(true, 4, 2, "badsum")
			r.inj = testInjector(f)
			r.peer.Store(peer)

			r.sendFakes(peer)

			asked := f.asked()
			if len(asked) == 0 {
				t.Fatal("no badsum decoy was framed at all — the injector was never asked for a route")
			}
			for _, a := range asked {
				if a != peer.IP.String() {
					t.Fatalf("a badsum decoy was L2-framed for %s; it must follow the address the tunnel "+
						"routes to (%s), which is what forgedLink.send and the low-TTL decoy both use — "+
						"framing it for the forged header dst sends it out a next hop of its own", a, peer.IP)
				}
			}
		})
	}
}
