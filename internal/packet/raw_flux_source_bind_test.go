//go:build linux

package packet

import (
	"log"
	"net"
	"strings"
	"testing"
)

// unusableIP is routable-looking but is not on any interface here, so the kernel refuses to bind it.
// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for exactly this.
const unusableIP = "192.0.2.77"

// usableLoopbackIP is bindable on any host — canBindSource asks the kernel, and loopback aliases are
// bindable even where InterfaceAddrs() reports only 127.0.0.1/8 (that is why it asks).
const usableLoopbackIP = "127.0.0.1"

// raw and flux STAMP the source IP — into a crafted IP header, or an IP_PKTINFO control message —
// instead of binding a socket to it, so an IP that is not on this host fails silently: stored, logged as
// a rotation, published as an active source the tunnel cannot use. On the udp and tcp raw profiles that
// is a TOTAL BLACKOUT. Each case below drives the REAL method the rotation timer or pin poller calls.
func TestRawAndFluxRefuseASourceThisHostCannotSendFrom(t *testing.T) {
	// A rotation that lands on an unusable source must not move the tunnel onto it, must not publish
	// the move, and must leave the working source healthy and current.
	t.Run("raw rotation undoes the move", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0, "")
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if got := srcOf(r.localIP.Load()); got != usableLoopbackIP {
			t.Fatalf("seeded source %q, want %s", got, usableLoopbackIP)
		}
		r.rotateSourceRaw(true)
		if got := srcOf(r.localIP.Load()); got != usableLoopbackIP {
			t.Errorf("the carrier now stamps %s, which this host cannot send from — on the udp/tcp raw profiles every packet is dropped from here on", got)
		}
		if cur := sp.current(); cur != usableLoopbackIP {
			t.Errorf("the pool's active source is %s but the packets still leave from %s: the panel names an address the tunnel is not using", cur, usableLoopbackIP)
		}
	})

	t.Run("flux rotation undoes the move", func(t *testing.T) {
		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0, "")
		f := &Flux{isClient: true}
		f.SetSourcePool(sp)
		if got := srcOf(f.localIP.Load()); got != usableLoopbackIP {
			t.Fatalf("seeded source %q, want %s", got, usableLoopbackIP)
		}
		f.rotateSourceFlux(true)
		if got := srcOf(f.localIP.Load()); got != usableLoopbackIP {
			t.Errorf("the carrier now stamps %s, which this host cannot send from", got)
		}
		if cur := sp.current(); cur != usableLoopbackIP {
			t.Errorf("the pool's active source is %s but the packets still leave from %s", cur, usableLoopbackIP)
		}
	})

	// An operator jump onto an unusable source must be ENDED rather than held for its whole TTL while
	// the tunnel is dark — the same treatment dropUnusableSource gives it on tcp.
	t.Run("raw pin onto an unusable source is abandoned", func(t *testing.T) {
		var sink syncBuf
		old := log.Writer()
		log.SetOutput(&sink)
		defer log.SetOutput(old)

		sp := NewPeerPool([]string{usableLoopbackIP, unusableIP}, 0, "")
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if !sp.selectEntry(unusableIP) {
			t.Fatal("selectEntry rejected a pool member")
		}
		if !sp.isPinned() {
			t.Fatal("Pin did not take — the rest of this case would be vacuous")
		}
		r.adoptSourceRaw()
		if got := srcOf(r.localIP.Load()); got == unusableIP {
			t.Error("the pin was adopted: the tunnel now stamps a source this host cannot send from, and on the udp/tcp raw profiles that is a silent blackout")
		}
		if sp.isPinned() {
			t.Error("the jump is still in progress: it holds the whole pinTTL forcing a source that cannot work, with nothing in the panel explaining why")
		}
		if got := sink.String(); !strings.Contains(got, unusableIP) {
			t.Errorf("nothing named the unusable source — the operator sees a dead tunnel and no reason.\nlog was:\n%s", got)
		}
	})

	// ...and the seed, which is the worst case: it is stamped from the FIRST packet, so on the
	// checksum-binding profiles the tunnel never comes up at all.
	t.Run("raw seed refuses an unusable first entry", func(t *testing.T) {
		sp := NewPeerPool([]string{unusableIP, usableLoopbackIP}, 0, "")
		r := &Raw{isClient: true}
		r.link = &directLink{r: r}
		r.SetSourcePool(sp)
		if got := srcOf(r.localIP.Load()); got == unusableIP {
			t.Error("the pool's first entry was seeded unchecked: every packet from the very first one carries a source this host cannot send from")
		}
	})

	t.Run("flux seed refuses an unusable first entry", func(t *testing.T) {
		sp := NewPeerPool([]string{unusableIP, usableLoopbackIP}, 0, "")
		f := &Flux{isClient: true}
		f.SetSourcePool(sp)
		if got := srcOf(f.localIP.Load()); got == unusableIP {
			t.Error("the pool's first entry was seeded unchecked")
		}
	})
}

func srcOf(a *net.IPAddr) string {
	if a == nil {
		return ""
	}
	return a.IP.String()
}
